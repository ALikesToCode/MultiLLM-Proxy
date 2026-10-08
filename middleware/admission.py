"""Explicit post-authentication admission hook for the Flask registrar."""
import json

from flask import Response

from services.admission_leases import AdmissionError


def admission_error_response(error):
    headers = {"Cache-Control": "no-store"}
    if error.status == 429 and error.retry_after is not None:
        headers["Retry-After"] = str(error.retry_after)
    return Response(json.dumps({"error": {"code": error.code, "message": "Concurrency admission failed."}}),
                    status=error.status, headers=headers, content_type="application/json")


class _LeasedIterable:
    def __init__(self, source, lease):
        self.source, self.lease = source, lease
        self.iterator = None
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        if self.closed:
            raise StopIteration
        try:
            self.lease.check()
            if self.iterator is None:
                self.iterator = iter(self.source)
            chunk = next(self.iterator)
            self.lease.check()
            return chunk
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            close = getattr(self.source, "close", None)
            if close:
                close()
        finally:
            self.lease.release()


def dispatch_with_admission(identity, dispatch, client, *, on_lost=None):
    """Identity is supplied after auth/routing; dispatch returns a normalized Response.

    The registrar calls this before dispatch/preflight and supplies transport cancellation
    through on_lost. Flask/WSGI detects disconnects on iteration or response close.
    """
    try:
        lease = client.acquire(identity, on_lost=on_lost)
    except AdmissionError as error:
        return admission_error_response(error)
    if lease is None:
        return dispatch()
    response = None
    try:
        lease.check()
        response = dispatch()
        lease.check()
        if not isinstance(response, Response):
            raise TypeError("Admission dispatch must return a normalized Response")
        if response.is_streamed:
            response.response = _LeasedIterable(response.response, lease)
        else:
            lease.release()
        return response
    except BaseException as error:
        try:
            if response is not None and hasattr(response, "close"):
                response.close()
        finally:
            lease.release()
        if isinstance(error, AdmissionError):
            return admission_error_response(error)
        raise


class _ReleaseOnce:
    """Transfer one release operation from request setup to the response body."""

    def __init__(self, lease):
        self.lease = lease
        self.closed = False
        self.transferred = False

    def check(self):
        self.lease.check()

    def release(self):
        if not self.closed:
            self.closed = True
            self.lease.release()


def register_admission(app):
    from flask import g
    from services.admission_leases import AdmissionClient, admission_settings
    from services.admission_request import request_identity
    from services.request_cancellation import RequestCancellation

    app.extensions.setdefault("admission_client", AdmissionClient())

    def admit():
        settings = admission_settings()
        if not settings.enabled or not settings.limited():
            return None
        identity = request_identity(settings)
        if identity is None or not settings.limited(identity.model_group):
            return None
        owner = g.gateway_cancellation = RequestCancellation()
        try:
            lease = app.extensions["admission_client"].acquire(identity, on_lost=owner.cancel)
            if lease is not None:
                g.gateway_admission_lease = _ReleaseOnce(lease)
                g.gateway_admission_lease.check()
        except AdmissionError as error:
            lease = getattr(g, "gateway_admission_lease", None)
            if lease is not None:
                lease.release()
            return admission_error_response(error)
        return None

    app.extensions.setdefault("gateway_after_authentication", []).append(admit)
    app.register_error_handler(AdmissionError, admission_error_response)

    @app.after_request
    def finish_admission(response):
        lease = getattr(g, "gateway_admission_lease", None)
        if lease is None:
            return response
        try:
            lease.check()
        except AdmissionError as error:
            response.close()
            lease.release()
            return admission_error_response(error)
        if response.is_streamed:
            response.response = _LeasedIterable(response.response, lease)
            response.call_on_close(response.response.close)
            lease.transferred = True
        else:
            lease.release()
        return response

    @app.teardown_request
    def abandon_admission(error):
        lease = getattr(g, "gateway_admission_lease", None)
        if lease is not None and not lease.transferred:
            lease.release()
