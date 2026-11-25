"""FI private DNS service transition. No public ingress or grant changes."""
OLD = 'mnebyvpn-fi-dns-routed.service'
NEW = 'mnebyvpn-fi-dns-country.service'

def switch(ops):
    ops.preflight()
    try:
        ops.mark()
        ops.stop(OLD)
        ops.start(NEW)
        ops.verify_candidate()
        ops.enable(NEW)
        ops.disable(OLD)
        ops.verify_commit()
    except BaseException:
        errors=[]
        for action in (lambda: ops.disable(NEW),lambda: ops.stop(NEW),
                       ops.unmark,lambda: ops.enable(OLD),lambda: ops.start(OLD),
                       ops.verify_restore):
            try: action()
            except BaseException as exc: errors.append(type(exc).__name__)
        if errors: raise RuntimeError('FI_COUNTRY_ROLLBACK_UNCONFIRMED') from None
        raise
