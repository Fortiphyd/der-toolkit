"""
routes.py
─────────
Flask Blueprint containing every implemented 2030.5 resource route.

Each route is wrapped with @enforce_policy which:
  1. Extracts the client cert from the WSGI environ (injected by ssl_server.py)
  2. Computes the LFDI
  3. Applies the Table-12 policy (cert required? registration required?)
  4. Checks vulnerability overrides from config.yaml
  5. Populates flask.g with (lfdi, cert_present, registered)
"""

import logging
from flask import Blueprint, request, g, current_app, Response

from auth import enforce_policy
import xml_responses as xr
import xml_parser as xp

log = logging.getLogger(__name__)
bp  = Blueprint("sep2", __name__)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _log_access(resource: str):
    cert = f"LFDI={g.lfdi}" if g.cert_present else "no-cert"
    reg  = "registered" if getattr(g, "registered", False) else "unregistered"
    log.info("%s %s  [%s, %s]", request.method, resource, cert, reg)


def _parse_body(route: str):
    """
    Parse the XML request body and return (ParseResult, error_Response|None).
    If the safe parser blocks an attack, the error Response contains the reason.
    If the vulnerable parser resolves entities, telltales are logged.
    """
    body = request.get_data()
    if not body:
        return None, xr.error_response("BadRequest", "Empty request body", 400)

    cfg    = current_app.config["SEP2_CFG"]
    result = xp.parse_request_xml(body, cfg)

    if not result.success:
        if result.blocked_reason:
            log.warning("XML attack blocked on %s: %s", route, result.blocked_reason)
            return result, xr.error_response(
                "BadRequest",
                f"XML parse error: {result.blocked_reason} – {result.error}",
                400,
            )
        return result, xr.error_response(
            "BadRequest", f"XML parse error: {result.error}", 400,
        )

    if result.external_uris:
        log.warning("XXE FIRED on %s – URIs resolved: %s", route, result.external_uris)
    for tag, val in result.resolved_entity_values.items():
        log.warning("XXE exfil candidate in <%s>: %.120s", tag, val)

    return result, None


def _404(resource: str) -> Response:
    return xr.error_response("NotFound", f"{resource} not found", 404)


# ──────────────────────────────────────────────────────────────────────────────
# Open resources – no cert required
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/dcap", methods=["GET"])
@enforce_policy
def dcap():
    _log_access("/dcap")
    return xr.dcap_response()


@bp.route("/tm", methods=["GET"])
@enforce_policy
def time():
    _log_access("/tm")
    return xr.time_response()


@bp.route("/msg", methods=["GET"])
@enforce_policy
def msg_list():
    _log_access("/msg")
    return xr.msg_list_response()


@bp.route("/msg/<prog_id>", methods=["GET"])
@enforce_policy
def msg_program(prog_id):
    _log_access(f"/msg/{prog_id}")
    return xr.msg_program_response(prog_id)


@bp.route("/msg/<prog_id>/txtmsg", methods=["GET"])
@enforce_policy
def msg_txtmsg(prog_id):
    _log_access(f"/msg/{prog_id}/txtmsg")
    return xr.txt_msg_list_response(prog_id)


@bp.route("/ps", methods=["GET"])
@enforce_policy
def ps():
    _log_access("/ps")
    return xr.ps_response()


# ──────────────────────────────────────────────────────────────────────────────
# /edev  –  EndDevice list
# GET  – open
# POST – cert required (not registration)
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/edev", methods=["GET", "POST"])
@enforce_policy
def edev_list():
    _log_access("/edev")
    if request.method == "GET":
        return xr.edev_list_response()
    # POST – device self-registration; parse the submitted EndDevice XML
    result, err = _parse_body("/edev")
    if err:
        return err
    # Echo the submitted lFDI back in the 201 response.
    # When XXE fires, entity content lands in the tree as the lFDI text, so it
    # appears verbatim in the response body — making the vulnerability directly
    # observable rather than only visible in server logs.
    submitted_lfdi = _extract_text(result.tree, "lFDI") or "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    return xr.edev_created_response("99", submitted_lfdi)


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}/sub  –  Subscription creation  (cert required, no registration)
# This is one of the most natural XML-accepting surfaces: a client POSTs a
# Subscription resource describing which notifications it wants.
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/edev/<dev_id>/sub", methods=["GET", "POST"])
@enforce_policy
def edev_sub(dev_id):
    _log_access(f"/edev/{dev_id}/sub")
    if request.method == "GET":
        return xr.sub_list_response(dev_id)
    result, err = _parse_body(f"/edev/{dev_id}/sub")
    if err:
        return err
    # Echo subscribedResource back so XXE content is visible in the response.
    subscribed = _extract_text(result.tree, "subscribedResource") or f"/edev/{dev_id}/der"
    return xr.sub_created_response(dev_id, subscribed)


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}  –  cert required, NO registration check
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/edev/<dev_id>", methods=["GET"])
@enforce_policy
def edev(dev_id):
    _log_access(f"/edev/{dev_id}")
    return xr.edev_response(dev_id)


@bp.route("/edev/<dev_id>/reg", methods=["GET"])
@enforce_policy
def edev_reg(dev_id):
    _log_access(f"/edev/{dev_id}/reg")
    return xr.edev_reg_response(dev_id)


@bp.route("/edev/<dev_id>/fsa", methods=["GET"])
@enforce_policy
def edev_fsa(dev_id):
    _log_access(f"/edev/{dev_id}/fsa")
    return xr.edev_fsa_response(dev_id)


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}/der  –  cert + registration required
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/edev/<dev_id>/der", methods=["GET"])
@enforce_policy
def der_list(dev_id):
    _log_access(f"/edev/{dev_id}/der")
    return xr.der_list_response(dev_id)


@bp.route("/edev/<dev_id>/der/<der_id>/ctrl", methods=["GET"])
@enforce_policy
def der_ctrl_list(dev_id, der_id):
    _log_access(f"/edev/{dev_id}/der/{der_id}/ctrl")
    # reuse the derc list body for DER-level controls
    return xr.derc_list_response(dev_id)


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}/derc  –  DERControl list  (cert + registration)
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/edev/<dev_id>/derc", methods=["GET"])
@enforce_policy
def derc_list(dev_id):
    _log_access(f"/edev/{dev_id}/derc")
    return xr.derc_list_response(dev_id)


@bp.route("/edev/<dev_id>/derc/<ctrl_id>", methods=["GET"])
@enforce_policy
def derc_item(dev_id, ctrl_id):
    _log_access(f"/edev/{dev_id}/derc/{ctrl_id}")
    return xr.derc_list_response(dev_id)   # simplified single-item


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}/log  –  LogEventList  (cert + registration)
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/edev/<dev_id>/log", methods=["GET"])
@enforce_policy
def log_events(dev_id):
    _log_access(f"/edev/{dev_id}/log")
    return xr.log_event_list_response(dev_id)


# ──────────────────────────────────────────────────────────────────────────────
# /upt  –  UsagePointList  (cert + registration)
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/upt", methods=["GET"])
@enforce_policy
def upt_list():
    _log_access("/upt")
    return xr.upt_list_response()


@bp.route("/upt/<upt_id>", methods=["GET"])
@enforce_policy
def upt(upt_id):
    _log_access(f"/upt/{upt_id}")
    return xr.upt_response(upt_id)


@bp.route("/upt/<upt_id>/mr", methods=["GET"])
@enforce_policy
def meter_reading_list(upt_id):
    _log_access(f"/upt/{upt_id}/mr")
    return xr.meter_reading_list_response(upt_id)


@bp.route("/upt/<upt_id>/mr/<mr_id>/r", methods=["GET"])
@enforce_policy
def reading_list(upt_id, mr_id):
    _log_access(f"/upt/{upt_id}/mr/{mr_id}/r")
    return xr.reading_list_response(upt_id, mr_id)


# ──────────────────────────────────────────────────────────────────────────────
# /bill  –  BillingPeriodList  (cert + registration)
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/bill", methods=["GET"])
@enforce_policy
def bill_list():
    _log_access("/bill")
    return xr.bill_list_response()


# ──────────────────────────────────────────────────────────────────────────────
# /sdev  –  SelfDevice  (cert, no registration)
# ──────────────────────────────────────────────────────────────────────────────

@bp.route("/sdev", methods=["GET"])
@enforce_policy
def sdev():
    _log_access("/sdev")
    return xr.sdev_response()


# ──────────────────────────────────────────────────────────────────────────────
# Catch-all 404
# ──────────────────────────────────────────────────────────────────────────────

@bp.app_errorhandler(404)
def not_found(e):
    return xr.error_response("NotFound", str(e), 404)


@bp.app_errorhandler(405)
def method_not_allowed(e):
    return xr.error_response("MethodNotAllowed", str(e), 405)


# ──────────────────────────────────────────────────────────────────────────────
# Tree extraction helper
# ──────────────────────────────────────────────────────────────────────────────

def _extract_text(tree, local_name: str) -> str | None:
    """
    Find the first element with the given local name (ignoring namespace) in
    an lxml or stdlib ElementTree element, and return its text content.
    Returns None if not found or tree is None.
    """
    if tree is None:
        return None
    # lxml _Element and stdlib Element both support .iter()
    for el in tree.iter():
        # Strip namespace: '{urn:...}lFDI' → 'lFDI'
        tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
        if tag == local_name:
            return el.text
    return None
