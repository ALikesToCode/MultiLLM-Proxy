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
