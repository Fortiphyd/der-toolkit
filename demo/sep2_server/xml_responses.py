"""
xml_responses.py
────────────────
Builds minimal but spec-compliant IEEE 2030.5 XML responses.

All elements live in the canonical namespace:
    urn:ieee:std:2030.5:ns

List resources carry  all="N" results="N"  attributes so the mapper's
pagination logic is exercised.

Resource hrefs are absolute paths (no host) matching the Flask route tree.
"""

from flask import Response
from datetime import datetime, timezone

NS   = "urn:ieee:std:2030.5:ns"
NSXS = "http://www.w3.org/2001/XMLSchema-instance"


def _xml(body: str) -> Response:
    payload = f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n'
    return Response(payload, content_type="application/sep+xml; charset=utf-8")


def error_response(error_type: str, detail: str, status: int = 400) -> Response:
    body = (
        f'<Error xmlns="{NS}">\n'
        f'  <code>{status}</code>\n'
        f'  <message>{error_type}: {detail}</message>\n'
        f'</Error>'
    )
    payload = f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n'
    return Response(payload, status=status, content_type="application/sep+xml; charset=utf-8")


def _now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


# ──────────────────────────────────────────────────────────────────────────────
# /dcap  –  DeviceCapability
# ──────────────────────────────────────────────────────────────────────────────

def dcap_response() -> Response:
    body = f"""<DeviceCapability xmlns="{NS}" href="/dcap">
  <EndDeviceListLink all="2" href="/edev"/>
  <MirrorUsagePointListLink all="0" href="/mup"/>
  <SelfDeviceLink href="/sdev"/>
  <TimeLink href="/tm"/>
  <UsagePointListLink all="1" href="/upt"/>
  <MessagingProgramListLink all="1" href="/msg"/>
  <ResponseSetListLink all="0" href="/rsps"/>
  <DemandResponseProgramListLink all="0" href="/dr"/>
  <BillingPeriodListLink all="1" href="/bill"/>
</DeviceCapability>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /tm  –  Time
# ──────────────────────────────────────────────────────────────────────────────

def time_response() -> Response:
    now = _now_epoch()
    body = f"""<Time xmlns="{NS}" href="/tm">
  <currentTime>{now}</currentTime>
  <dstEndTime>1730610000</dstEndTime>
  <dstOffset>3600</dstOffset>
  <dstStartTime>1710316800</dstStartTime>
  <localTime>{now}</localTime>
  <quality>7</quality>
  <tzOffset>-18000</tzOffset>
</Time>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /msg  –  MessagingProgramList
# ──────────────────────────────────────────────────────────────────────────────

def msg_list_response() -> Response:
    body = f"""<MessagingProgramList xmlns="{NS}" href="/msg" all="1" results="1">
  <MessagingProgram href="/msg/0" mRID="A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4">
    <ActiveTextMessageListLink all="1" href="/msg/0/actmsg"/>
    <primacy>0</primacy>
    <TextMessageListLink all="1" href="/msg/0/txtmsg"/>
  </MessagingProgram>
</MessagingProgramList>"""
    return _xml(body)


def msg_program_response(prog_id: str) -> Response:
    body = f"""<MessagingProgram xmlns="{NS}" href="/msg/{prog_id}"
    mRID="A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4">
  <ActiveTextMessageListLink all="1" href="/msg/{prog_id}/actmsg"/>
  <primacy>0</primacy>
  <TextMessageListLink all="1" href="/msg/{prog_id}/txtmsg"/>
</MessagingProgram>"""
    return _xml(body)


def txt_msg_list_response(prog_id: str) -> Response:
    now = _now_epoch()
    body = f"""<TextMessageList xmlns="{NS}" href="/msg/{prog_id}/txtmsg" all="1" results="1">
  <TextMessage href="/msg/{prog_id}/txtmsg/0" creationTime="{now}">
    <priority>0</priority>
    <textMessage>SEP2 test server operational. This is a test message.</textMessage>
  </TextMessage>
</TextMessageList>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /ps  –  PricingProgramList  (open, no cert)
# ──────────────────────────────────────────────────────────────────────────────

def ps_response() -> Response:
    body = f"""<PricingProgramList xmlns="{NS}" href="/ps" all="1" results="1">
  <PricingProgram href="/ps/0" mRID="F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0">
    <ActivePricingScheduleListLink all="0" href="/ps/0/actsched"/>
    <primacy>0</primacy>
    <PricingScheduleListLink all="0" href="/ps/0/sched"/>
  </PricingProgram>
</PricingProgramList>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /edev  –  EndDeviceList
# ──────────────────────────────────────────────────────────────────────────────

def edev_list_response() -> Response:
    body = f"""<EndDeviceList xmlns="{NS}" href="/edev" all="2" results="2">
  <EndDevice href="/edev/0" subscribable="0">
    <ConfigurationLink href="/edev/0/cfg"/>
    <DERListLink all="1" href="/edev/0/der"/>
    <DeviceStatusLink href="/edev/0/dstat"/>
    <FunctionSetAssignmentsListLink all="1" href="/edev/0/fsa"/>
    <IPInterfaceListLink all="1" href="/edev/0/ns"/>
    <LoadShedAvailabilityListLink all="0" href="/edev/0/lsl"/>
    <LogEventListLink all="3" href="/edev/0/log"/>
    <PowerStatusLink href="/edev/0/ps"/>
    <RegistrationLink href="/edev/0/reg"/>
    <deviceCategory>0000000000000010</deviceCategory>
    <lFDI>AABBCCDD112233445566778899AABBCCDD112233</lFDI>
    <sFDI>123456789012</sFDI>
  </EndDevice>
  <EndDevice href="/edev/1" subscribable="0">
    <ConfigurationLink href="/edev/1/cfg"/>
    <DERListLink all="1" href="/edev/1/der"/>
    <DeviceStatusLink href="/edev/1/dstat"/>
    <FunctionSetAssignmentsListLink all="1" href="/edev/1/fsa"/>
    <IPInterfaceListLink all="1" href="/edev/1/ns"/>
    <LoadShedAvailabilityListLink all="0" href="/edev/1/lsl"/>
    <LogEventListLink all="0" href="/edev/1/log"/>
    <PowerStatusLink href="/edev/1/ps"/>
    <RegistrationLink href="/edev/1/reg"/>
    <deviceCategory>0000000000000040</deviceCategory>
    <lFDI>BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB</lFDI>
    <sFDI>987654321098</sFDI>
  </EndDevice>
</EndDeviceList>"""
    return _xml(body)


def edev_response(dev_id: str) -> Response:
    body = f"""<EndDevice xmlns="{NS}" href="/edev/{dev_id}" subscribable="0">
  <ConfigurationLink href="/edev/{dev_id}/cfg"/>
  <DERListLink all="1" href="/edev/{dev_id}/der"/>
  <DeviceStatusLink href="/edev/{dev_id}/dstat"/>
  <FunctionSetAssignmentsListLink all="1" href="/edev/{dev_id}/fsa"/>
  <IPInterfaceListLink all="1" href="/edev/{dev_id}/ns"/>
  <LoadShedAvailabilityListLink all="0" href="/edev/{dev_id}/lsl"/>
  <LogEventListLink all="3" href="/edev/{dev_id}/log"/>
  <PowerStatusLink href="/edev/{dev_id}/ps"/>
  <RegistrationLink href="/edev/{dev_id}/reg"/>
  <deviceCategory>0000000000000010</deviceCategory>
  <lFDI>AABBCCDD112233445566778899AABBCCDD112233</lFDI>
  <sFDI>123456789012</sFDI>
</EndDevice>"""
    return _xml(body)


def edev_created_response(dev_id: str, lfdi: str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC") -> Response:
    """201 response body for POST /edev.
    lfdi is echoed from the submitted XML — if XXE fired, this will contain
    the resolved entity content (e.g. /etc/passwd) rather than a real LFDI.
    """
    body = f"""<EndDevice xmlns="{NS}" href="/edev/{dev_id}">
  <RegistrationLink href="/edev/{dev_id}/reg"/>
  <lFDI>{lfdi}</lFDI>
  <sFDI>111111111111</sFDI>
</EndDevice>"""
    return Response(
        f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n',
        status=201,
        headers={"Location": f"/edev/{dev_id}"},
        content_type="application/sep+xml; charset=utf-8",
    )


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}/reg  –  Registration
# ──────────────────────────────────────────────────────────────────────────────

def edev_reg_response(dev_id: str) -> Response:
    now = _now_epoch()
    body = f"""<Registration xmlns="{NS}" href="/edev/{dev_id}/reg">
  <dateTimeRegistered>{now - 86400}</dateTimeRegistered>
  <pIN>12345</pIN>
</Registration>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}/fsa  –  FunctionSetAssignmentsList
# ──────────────────────────────────────────────────────────────────────────────

def edev_fsa_response(dev_id: str) -> Response:
    body = f"""<FunctionSetAssignmentsList xmlns="{NS}" href="/edev/{dev_id}/fsa" all="1" results="1">
  <FunctionSetAssignments href="/edev/{dev_id}/fsa/0" mRID="0102030405060708090A0B0C0D0E0F10">
    <DERProgramListLink all="1" href="/edev/{dev_id}/fsa/0/derp"/>
    <MessagingProgramListLink all="1" href="/msg"/>
    <PricingProgramListLink all="1" href="/ps"/>
    <ResponseSetListLink all="0" href="/rsps"/>
    <SupplyInterruptionOverrideListLink all="0" href="/edev/{dev_id}/fsa/0/sio"/>
    <TariffProfileListLink all="0" href="/tp"/>
    <TimeLink href="/tm"/>
    <UsagePointListLink all="1" href="/upt"/>
  </FunctionSetAssignments>
</FunctionSetAssignmentsList>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}/der  –  DERList  (cert + registration required)
# ──────────────────────────────────────────────────────────────────────────────

def der_list_response(dev_id: str) -> Response:
    body = f"""<DERList xmlns="{NS}" href="/edev/{dev_id}/der" all="1" results="1">
  <DER href="/edev/{dev_id}/der/0" subscribable="0">
    <AssociatedDERProgramListLink all="1" href="/edev/{dev_id}/der/0/derp"/>
    <CurrentDERProgramLink href="/edev/{dev_id}/der/0/derp/0"/>
    <DERAvailabilityLink href="/edev/{dev_id}/der/0/dera"/>
    <DERCapabilityLink href="/edev/{dev_id}/der/0/derc"/>
    <DERControlListLink all="2" href="/edev/{dev_id}/der/0/ctrl"/>
    <DERSettingsLink href="/edev/{dev_id}/der/0/derg"/>
    <DERStatusLink href="/edev/{dev_id}/der/0/ders"/>
    <AssociatedUsagePointLink href="/upt/0"/>
  </DER>
</DERList>"""
    return _xml(body)


def derc_list_response(dev_id: str) -> Response:
    """DERControl list for the device – requires cert + registration."""
    now = _now_epoch()
    body = f"""<DERControlList xmlns="{NS}" href="/edev/{dev_id}/derc" all="2" results="2">
  <DERControl href="/edev/{dev_id}/derc/0" mRID="DEADBEEF00000000DEADBEEF00000001">
    <DERControlBase>
      <opModConnect>true</opModConnect>
      <opModEnergize>true</opModEnergize>
      <opModFixedW>5000</opModFixedW>
    </DERControlBase>
    <interval>
      <duration>3600</duration>
      <start>{now}</start>
    </interval>
  </DERControl>
  <DERControl href="/edev/{dev_id}/derc/1" mRID="DEADBEEF00000000DEADBEEF00000002">
    <DERControlBase>
      <opModConnect>false</opModConnect>
      <opModEnergize>false</opModEnergize>
    </DERControlBase>
    <interval>
      <duration>3600</duration>
      <start>{now + 3600}</start>
    </interval>
  </DERControl>
</DERControlList>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}/log  –  LogEventList  (cert + registration)
# ──────────────────────────────────────────────────────────────────────────────

def log_event_list_response(dev_id: str) -> Response:
    now = _now_epoch()
    body = f"""<LogEventList xmlns="{NS}" href="/edev/{dev_id}/log" all="3" results="3">
  <LogEvent href="/edev/{dev_id}/log/0" createdDateTime="{now - 7200}">
    <details>Device initialised</details>
    <functionSet>0</functionSet>
    <importance>0</importance>
    <logEventCode>1</logEventCode>
    <logEventID>0</logEventID>
    <logEventPEN>40732</logEventPEN>
    <profileID>2</profileID>
  </LogEvent>
  <LogEvent href="/edev/{dev_id}/log/1" createdDateTime="{now - 3600}">
    <details>DER programme applied</details>
    <functionSet>61</functionSet>
    <importance>0</importance>
    <logEventCode>2</logEventCode>
    <logEventID>1</logEventID>
    <logEventPEN>40732</logEventPEN>
    <profileID>2</profileID>
  </LogEvent>
  <LogEvent href="/edev/{dev_id}/log/2" createdDateTime="{now - 60}">
    <details>Heartbeat</details>
    <functionSet>0</functionSet>
    <importance>0</importance>
    <logEventCode>3</logEventCode>
    <logEventID>2</logEventID>
    <logEventPEN>40732</logEventPEN>
    <profileID>2</profileID>
  </LogEvent>
</LogEventList>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /upt  –  UsagePointList  (cert + registration)
# ──────────────────────────────────────────────────────────────────────────────

def upt_list_response() -> Response:
    body = f"""<UsagePointList xmlns="{NS}" href="/upt" all="1" results="1">
  <UsagePoint href="/upt/0" subscribable="0">
    <MeterReadingListLink all="2" href="/upt/0/mr"/>
    <ServiceCategoryKind>0</ServiceCategoryKind>
    <status>0</status>
    <deviceLFDI>AABBCCDD112233445566778899AABBCCDD112233</deviceLFDI>
  </UsagePoint>
</UsagePointList>"""
    return _xml(body)


def upt_response(upt_id: str) -> Response:
    body = f"""<UsagePoint xmlns="{NS}" href="/upt/{upt_id}" subscribable="0">
  <MeterReadingListLink all="2" href="/upt/{upt_id}/mr"/>
  <ServiceCategoryKind>0</ServiceCategoryKind>
  <status>0</status>
  <deviceLFDI>AABBCCDD112233445566778899AABBCCDD112233</deviceLFDI>
</UsagePoint>"""
    return _xml(body)


def meter_reading_list_response(upt_id: str) -> Response:
    now = _now_epoch()
    body = f"""<MeterReadingList xmlns="{NS}" href="/upt/{upt_id}/mr" all="2" results="2">
  <MeterReading href="/upt/{upt_id}/mr/0" subscribable="0">
    <ReadingTypeLink href="/upt/{upt_id}/mr/0/rt"/>
    <mRID>0102030405060708090A0B0C0D0E0F10</mRID>
  </MeterReading>
  <MeterReading href="/upt/{upt_id}/mr/1" subscribable="0">
    <ReadingTypeLink href="/upt/{upt_id}/mr/1/rt"/>
    <mRID>1112131415161718191A1B1C1D1E1F20</mRID>
  </MeterReading>
</MeterReadingList>"""
    return _xml(body)


def reading_list_response(upt_id: str, mr_id: str) -> Response:
    now = _now_epoch()
    body = f"""<ReadingList xmlns="{NS}" href="/upt/{upt_id}/mr/{mr_id}/r" all="2" results="2">
  <Reading href="/upt/{upt_id}/mr/{mr_id}/r/0">
    <localID>0001</localID>
    <timePeriod>
      <duration>900</duration>
      <start>{now - 900}</start>
    </timePeriod>
    <value>12345</value>
  </Reading>
  <Reading href="/upt/{upt_id}/mr/{mr_id}/r/1">
    <localID>0002</localID>
    <timePeriod>
      <duration>900</duration>
      <start>{now - 1800}</start>
    </timePeriod>
    <value>12280</value>
  </Reading>
</ReadingList>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /bill  –  BillingPeriodList  (cert + registration)
# ──────────────────────────────────────────────────────────────────────────────

def bill_list_response() -> Response:
    now = _now_epoch()
    body = f"""<BillingPeriodList xmlns="{NS}" href="/bill" all="1" results="1">
  <BillingPeriod href="/bill/0">
    <billLastPeriod>4523</billLastPeriod>
    <billToDate>1203</billToDate>
    <interval>
      <duration>2592000</duration>
      <start>{now - (now % 2592000)}</start>
    </interval>
    <statusTimeStamp>{now - 86400}</statusTimeStamp>
  </BillingPeriod>
</BillingPeriodList>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /sdev  –  SelfDevice  (cert, no registration)
# ──────────────────────────────────────────────────────────────────────────────

def sdev_response() -> Response:
    body = f"""<SelfDevice xmlns="{NS}" href="/sdev" subscribable="0">
  <ConfigurationLink href="/sdev/cfg"/>
  <DERListLink all="0" href="/sdev/der"/>
  <DeviceStatusLink href="/sdev/dstat"/>
  <FunctionSetAssignmentsListLink all="1" href="/sdev/fsa"/>
  <IPInterfaceListLink all="1" href="/sdev/ns"/>
  <LoadShedAvailabilityListLink all="0" href="/sdev/lsl"/>
  <LogEventListLink all="0" href="/sdev/log"/>
  <PowerStatusLink href="/sdev/ps"/>
  <deviceCategory>0000000000000080</deviceCategory>
  <lFDI>0000000000000000000000000000000000000000</lFDI>
  <sFDI>000000000001</sFDI>
</SelfDevice>"""
    return _xml(body)


# ──────────────────────────────────────────────────────────────────────────────
# /edev/{id}/sub  –  SubscriptionList / Subscription
# ──────────────────────────────────────────────────────────────────────────────

def sub_list_response(dev_id: str) -> Response:
    body = f"""<SubscriptionList xmlns="{NS}" href="/edev/{dev_id}/sub" all="0" results="0">
</SubscriptionList>"""
    return _xml(body)


def sub_created_response(dev_id: str, subscribed_resource: str | None = None) -> Response:
    sub_id = "1"
    subscribed_resource = subscribed_resource or f"/edev/{dev_id}/der"
    body = f"""<Subscription xmlns="{NS}" href="/edev/{dev_id}/sub/{sub_id}">
  <subscribedResource>{subscribed_resource}</subscribedResource>
  <limit>10</limit>
</Subscription>"""
    return Response(
        f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n',
        status=201,
        headers={"Location": f"/edev/{dev_id}/sub/{sub_id}"},
        content_type="application/sep+xml; charset=utf-8",
    )
