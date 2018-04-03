from pycomm.cip.cip_base import *


class Driver(Base):

    def __init__(self):
        super(Driver, self).__init__()

        self._buffer = {}
        self._get_template_in_progress = False
        self.__version__ = '0.2'

    def get_attribute_single(self, clss, inst, attr):
        self.clear()
        message_request = [
            bytes([0x0E]),  # get attribute single service
            bytes([0x03]),  # the Request Path Size length in word
            bytes([0x20, clss, 0x24, inst, 0x30, attr]),  # the request path
        ]
        packet = build_common_packet_format(
            DATA_ITEM['Unconnected'],
            b''.join(message_request),
            ADDRESS_ITEM['UCMM'],)
        if not self.send_rr_data(packet):
            self._status = (6, "send_rr_data failed")
            logger.warning(self._status)
            raise DataError("send_rr_data failed")
        if self._status[0] == SUCCESS:
            # TODO: use packet to provide context for raw value(s)
            return self._reply[-(self._reply[38] - 4):]
        else:
            return None

    def _check_reply(self):
        """ check the reply message for error

        """
        self._more_packets_available = False
        try:
            if self._reply is None:
                self._status = (3, '{} without reply'.format(
                    REPLAY_INFO[unpack_dint(self._message[:2])]))
                return False
            # Get the type of command
            typ = unpack_uint(self._reply[:2])

            # Encapsulation status check
            if unpack_dint(self._reply[8:12]) != SUCCESS:
                self._status = (3, "{0} reply status:{1}".format(
                    REPLAY_INFO[typ],
                    SERVICE_STATUS[unpack_dint(self._reply[8:12])]))
                return False

            # Command Specific Status check
            if typ == unpack_uint(ENCAPSULATION_COMMAND["send_rr_data"]):
                status = unpack_usint(self._reply[42:43])
                if status != SUCCESS:
                    status_msg = "send_rr_data reply:{0} - Extend status:{1}"
                    self._status = (3, status_msg.format(
                        SERVICE_STATUS[status],
                        get_extended_status(self._reply, 42)))
                    return False
                else:
                    return True
            return True
        except Exception as e:
            raise DataError(e)
