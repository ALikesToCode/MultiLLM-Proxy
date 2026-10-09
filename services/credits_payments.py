"""Verified processor evidence credits the same owner used by request admission."""
from services import credits_ledger as ledger
from services.enterprise_contract import AuthorityResult, PaymentEvent


def payment_callback(store=None):
    """Construct a lazy callback; registration does not open or query storage."""
    def apply(event):
        if type(event) is not PaymentEvent or event.verified is not True:
            raise TypeError('Verified PaymentEvent required')
        if not ledger.enabled():
            raise ledger.CreditsError('credits_disabled', 404)
        if event.currency != 'USD':
            raise ledger.CreditsError('invalid_credits_request', 400)
        from services.credits_admission import CreditAdmissionError, _retry
        authority = store if store is not None else ledger.open_store()
        owner = ledger.context_owner(event.context)

        def append(operation):
            try:
                return authority.append_payment(owner, event.kind, operation.amount,
                    operation.operation_id, operation.revision, scoped_id=operation.scoped_id,
                    processor_id=event.processor_id)
            except ledger.CreditsError as error:
                if error.code == 'credits_revision_mismatch' and error.status != 412:
                    raise CreditAdmissionError() from None
                raise

        _retry(authority, event.context, event.scoped_id, event.idempotency_id, event.amount,
               append)
        return AuthorityResult(event.context, event.scoped_id, event.revision + 1,
                               event.idempotency_id, True)
    return apply
