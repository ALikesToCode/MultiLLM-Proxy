"""SCIM bearer API with no dashboard or cookie-based authorisation."""
import json

from flask import Blueprint, Response, current_app, g, request

from services import scim_provisioning as scim


def response(body=None, status=200, resource=None):
    result = Response("" if body is None else json.dumps(body, ensure_ascii=True), status=status,
                      content_type="application/scim+json")
    result.headers["Cache-Control"] = "no-store"
    if resource:
        result.headers["ETag"] = resource["meta"]["version"]
        if status == 201:
            result.headers["Location"] = resource["meta"]["location"]
    return result


def discovery(name, resource_id=None):
    definitions = []
    for kind, schema, attributes in (("User", scim.USER_SCHEMA, scim.USER_ATTRIBUTES),
                                      ("Group", scim.GROUP_SCHEMA, scim.GROUP_ATTRIBUTES)):
        if name == "Schemas":
            definitions.append({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
                                "id": schema, "name": kind, "attributes": _attributes(kind, attributes)})
        else:
            definitions.append({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                                "id": kind, "name": kind, "endpoint": "/" + kind + "s", "schema": schema,
                                "schemaExtensions": []})
    if name == "ServiceProviderConfig":
        if resource_id:
            raise scim.ScimError(404, "Resource not found")
        return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": 100}, "changePassword": {"supported": False},
                "sort": {"supported": False}, "etag": {"supported": True},
                "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token",
                                           "description": "Tenant-bound provisioning bearer token", "primary": True}]}
    if resource_id:
        for definition in definitions:
            if definition["id"] == resource_id:
                return definition
        raise scim.ScimError(404, "Resource not found")
    return {"schemas": [scim.LIST_SCHEMA], "totalResults": len(definitions),
            "startIndex": 1, "itemsPerPage": len(definitions), "Resources": definitions}


def _attributes(kind, attributes):
    values = []
    for name in sorted(attributes):
        complex_attribute = name in {"name", "emails", "members"}
        value = {"name": name, "type": "complex" if complex_attribute else "boolean" if name == "active" else "string",
                 "multiValued": name in {"emails", "members"}, "required": name == ("userName" if kind == "User" else "displayName"),
                 "mutability": "immutable" if name == "userName" else "readWrite", "returned": "default",
                 "uniqueness": "server" if name in {"externalId", "userName"} else "none"}
        if complex_attribute:
            names = {"name": ["formatted", "givenName", "familyName", "middleName", "honorificPrefix", "honorificSuffix"],
                     "emails": ["value", "type", "display", "primary"], "members": ["value", "display", "$ref"]}[name]
            value["subAttributes"] = [{"name": key, "type": "boolean" if key == "primary" else "string",
                                       "multiValued": False, "required": key == "value", "mutability": "readWrite",
                                       "returned": "default", "uniqueness": "none"} for key in names]
        values.append(value)
    return values


def register_scim_routes(app, *, service=None):
    """Mount explicit collaborators; an enabled unconfigured authority fails closed."""
    if service is not None:
        app.extensions["scim_service"] = service
    blueprint = Blueprint("scim", __name__, url_prefix="/scim/v2")

    def guard():
        if not request.path.startswith("/scim/v2/"):
            return None
        if not scim.enabled():
            return response(scim.ScimError(404, "Resource not found").body(), 404)
        try:
            g.scim_scope = scim.authenticate(request.headers.get("Authorization"))
            if request.method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
                raise scim.ScimError(405, "Method not allowed")
            if not request.endpoint or not request.endpoint.startswith("scim."):
                raise scim.ScimError(404, "Resource not found")
        except scim.ScimError as error:
            return response(error.body(), error.status)
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, guard)

    @blueprint.route("/<kind>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], provide_automatic_options=False)
    @blueprint.route("/<kind>/<path:resource_id>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], provide_automatic_options=False)
    def scim_resource(kind, resource_id=None):
        try:
            org, digest = g.scim_scope
            authority = current_app.extensions.get("scim_service")
            if authority is None:
                raise scim.ScimError(503, "SCIM authority unavailable")
            authority.ready()
            if kind in {"Schemas", "ResourceTypes", "ServiceProviderConfig"}:
                if request.method not in {"GET", "HEAD"}:
                    raise scim.ScimError(405, "Method not allowed")
                return response(discovery(kind, resource_id))
            if kind not in {"Users", "Groups"}:
                raise scim.ScimError(404, "Resource not found")
            return _resource_request(authority, org, digest, kind, resource_id)
        except scim.ScimError as error:
            return response(error.body(), error.status)
        except Exception:
            return response(scim.ScimError(503, "SCIM authority unavailable").body(), 503)

    csrf = app.extensions.get("csrf")
    if csrf is not None:
        csrf.exempt(blueprint)
    app.register_blueprint(blueprint)


def _resource_request(authority, org, digest, kind, resource_id):
    if request.method in {"GET", "HEAD"}:
        if resource_id is None:
            return response(authority.list(org, kind, request.args))
        resource = authority.get(org, kind, resource_id)
        return response(resource, resource=resource)
    body = None
    if request.method != "DELETE":
        if request.mimetype not in {"application/json", "application/scim+json"}:
            raise scim.ScimError(400, "JSON content type required", "invalidSyntax")
        if request.content_length is not None and request.content_length > scim.MAX_BODY:
            raise scim.ScimError(413, "SCIM body limit exceeded", "tooMany")
        raw = request.stream.read(scim.MAX_BODY + 1)
        if len(raw) > scim.MAX_BODY:
            raise scim.ScimError(413, "SCIM body limit exceeded", "tooMany")
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise scim.ScimError(400, "Invalid JSON", "invalidSyntax") from None
    if request.method == "POST" and resource_id is None:
        resource, created = authority.create(org, kind, body, digest)
        return response(resource, 201 if created else 200, resource)
    if request.method in {"PUT", "PATCH", "DELETE"} and resource_id is not None:
        resource = authority.update(org, kind, resource_id, body, patch=request.method == "PATCH",
                                    delete=request.method == "DELETE", if_match=request.headers.get("If-Match"),
                                    token_digest=digest)
        return response(None if request.method == "DELETE" else resource,
                        204 if request.method == "DELETE" else 200, resource)
    raise scim.ScimError(405, "Method not allowed")
