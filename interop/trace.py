from enum import Enum

import pyshark

cap = pyshark.FileCapture("../logs/sim/trace_node_left.pcap", display_filter="ip.dst==192.168.0.100 && quic")

class Direction(Enum):
  ALL = 0
  FROM_CLIENT = 1
  FROM_SERVER = 2

class TraceAnalyzer:
  _filename = ""

  def __init__(self, filename: str):
    self._filename = filename

  def _get_dirction_filter(self, d: Direction) -> str:
    if d == Direction.FROM_CLIENT:
      return "ip.src==192.168.0.100 && "
    elif d == Direction.FROM_SERVER:
      return "ip.src==192.168.100.100 && "
    else:
      return ""

  def get_retry(self, direction: Direction = Direction.ALL) -> pyshark.FileCapture:
    f = self._get_dirction_filter(direction) + "quic.long.packet_type==Retry"
    return pyshark.FileCapture(self._filename, display_filter=f)

  def get_initial(self, direction: Direction = Direction.ALL) -> pyshark.FileCapture:
    """ Get all Initial packets.
    Note that this might return coalesced packets. Filter by:
    packet.quic.long_packet_type == "0"
    """
    f = self._get_dirction_filter(direction) + "quic.long.packet_type==Initial"
    return pyshark.FileCapture(self._filename, display_filter=f)

  def get_handshake(self, direction: Direction = Direction.ALL) -> pyshark.FileCapture:
    """ Get all Initial packets.
    Note that this might return coalesced packets. Filter by:
    packet.quic.long_packet_type == "2"
    """
    f = self._get_dirction_filter(direction) + "quic.long.packet_type==Handshake"
    return pyshark.FileCapture(self._filename, display_filter=f)
