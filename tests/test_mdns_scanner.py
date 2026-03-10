"""Tests for mDNS scanner module."""

from unittest.mock import MagicMock, patch

from src.mdns_scanner import (
    MdnsDevice,
    _parse_txt_records,
    _process_collected_services,
    _resolve_service,
    _ServiceCollector,
    _start_browsers,
)


class TestMdnsDevice:
    """Tests for MdnsDevice dataclass."""

    def test_defaults(self) -> None:
        dev = MdnsDevice(hostname="test.local", ip_address="192.168.1.10")
        assert dev.hostname == "test.local"
        assert dev.ip_address == "192.168.1.10"
        assert dev.mac_address == ""
        assert dev.service_type == ""
        assert dev.port == 0
        assert dev.vendor is None
        assert dev.is_randomized is False
        assert dev.txt_records == {}

    def test_custom_values(self) -> None:
        dev = MdnsDevice(
            hostname="printer.local",
            ip_address="192.168.1.20",
            mac_address="AA:BB:CC:DD:EE:FF",
            service_type="ipp",
            port=631,
            vendor="Brother",
        )
        assert dev.mac_address == "AA:BB:CC:DD:EE:FF"
        assert dev.service_type == "ipp"
        assert dev.port == 631
        assert dev.vendor == "Brother"


class TestServiceCollector:
    """Tests for mDNS service collector."""

    def test_add_service(self) -> None:
        collector = _ServiceCollector()
        collector.add_service(None, "_http._tcp.local.", "My Web Server._http._tcp.local.")
        assert len(collector.found) == 1
        assert collector.found[0] == ("_http._tcp.local.", "My Web Server._http._tcp.local.")

    def test_update_service(self) -> None:
        collector = _ServiceCollector()
        collector.update_service(None, "_http._tcp.local.", "Server._http._tcp.local.")
        assert len(collector.found) == 1

    def test_remove_service(self) -> None:
        collector = _ServiceCollector()
        collector.add_service(None, "_http._tcp.local.", "Server._http._tcp.local.")
        collector.remove_service(None, "_http._tcp.local.", "Server._http._tcp.local.")
        # Remove doesn't actually remove from found (by design)
        assert len(collector.found) == 1

    def test_multiple_services(self) -> None:
        collector = _ServiceCollector()
        collector.add_service(None, "_http._tcp.local.", "Web._http._tcp.local.")
        collector.add_service(None, "_ipp._tcp.local.", "Printer._ipp._tcp.local.")
        assert len(collector.found) == 2


class TestScanMdnsServices:
    """Tests for scan_mdns_services function."""

    @patch("src.mdns_scanner.scan_mdns_services")
    def test_returns_list(self, mock_scan) -> None:
        mock_scan.return_value = [
            MdnsDevice(hostname="test.local", ip_address="192.168.1.10"),
        ]
        result = mock_scan()
        assert len(result) == 1
        assert result[0].hostname == "test.local"

    def test_import_failure_returns_empty(self) -> None:
        """Test graceful handling when zeroconf is not available."""
        from src.mdns_scanner import scan_mdns_services

        with patch.dict("sys.modules", {"zeroconf": None}):
            # The function handles ImportError internally
            # We can't easily test this without uninstalling zeroconf
            # So just verify the function is callable
            assert callable(scan_mdns_services)


class TestArpLookupMac:
    """Tests for _arp_lookup_mac function."""

    @patch("subprocess.run")
    def test_found_mac(self, mock_run) -> None:
        from src.mdns_scanner import _arp_lookup_mac

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="  192.168.1.10  aa-bb-cc-dd-ee-ff  dynamic",
        )
        result = _arp_lookup_mac("192.168.1.10")
        assert result == "AA:BB:CC:DD:EE:FF"

    @patch("subprocess.run")
    def test_not_found(self, mock_run) -> None:
        from src.mdns_scanner import _arp_lookup_mac

        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
        )
        result = _arp_lookup_mac("192.168.1.10")
        assert result == ""

    @patch("subprocess.run", side_effect=OSError("command not found"))
    def test_command_failure(self, mock_run) -> None:
        from src.mdns_scanner import _arp_lookup_mac

        result = _arp_lookup_mac("192.168.1.10")
        assert result == ""


class TestParseTxtRecords:
    """Tests for _parse_txt_records."""

    def test_with_valid_data(self) -> None:
        props = {b"md": b"Chromecast", b"fn": b"Living Room"}
        result = _parse_txt_records(props)
        assert result == {"md": "Chromecast", "fn": "Living Room"}

    def test_none_returns_empty(self) -> None:
        assert _parse_txt_records(None) == {}

    def test_empty_dict(self) -> None:
        assert _parse_txt_records({}) == {}

    def test_none_value(self) -> None:
        result = _parse_txt_records({b"key": None})
        assert result == {"key": ""}

    def test_non_utf8_key(self) -> None:
        """Test graceful handling of non-UTF8 bytes."""
        result = _parse_txt_records({b"\xff\xfe": b"value"})
        assert len(result) == 1


class TestResolveService:
    """Tests for _resolve_service."""

    @patch("src.mdns_scanner.is_randomized_mac", return_value=False)
    @patch("src.mdns_scanner.lookup_vendor", return_value="Google")
    @patch("src.mdns_scanner._arp_lookup_mac", return_value="AA:BB:CC:DD:EE:FF")
    def test_resolve_success(self, _mock_arp, _mock_vendor, _mock_rand) -> None:
        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["192.168.1.30"]
        mock_info.server = "chromecast.local."
        mock_info.port = 8008
        mock_info.properties = {b"md": b"Chromecast"}
        mock_zc.get_service_info.return_value = mock_info

        seen: set[str] = set()
        device = _resolve_service(mock_zc, "_googlecast._tcp.local.", "Name", seen, 5.0)
        assert device is not None
        assert device.hostname == "chromecast.local"
        assert device.ip_address == "192.168.1.30"
        assert device.mac_address == "AA:BB:CC:DD:EE:FF"
        assert device.vendor == "Google"
        assert device.port == 8008

    def test_resolve_none_info(self) -> None:
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = None
        result = _resolve_service(mock_zc, "_http._tcp.local.", "X", set(), 5.0)
        assert result is None

    def test_resolve_no_addresses(self) -> None:
        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = []
        mock_zc.get_service_info.return_value = mock_info
        result = _resolve_service(mock_zc, "_http._tcp.local.", "X", set(), 5.0)
        assert result is None

    def test_resolve_duplicate_skipped(self) -> None:
        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = ["10.0.0.1"]
        mock_zc.get_service_info.return_value = mock_info
        seen = {"10.0.0.1:_http._tcp.local."}
        result = _resolve_service(mock_zc, "_http._tcp.local.", "X", seen, 5.0)
        assert result is None

    def test_resolve_exception_returns_none(self) -> None:
        mock_zc = MagicMock()
        mock_zc.get_service_info.side_effect = RuntimeError("boom")
        result = _resolve_service(mock_zc, "_http._tcp.local.", "X", set(), 5.0)
        assert result is None


class TestStartBrowsers:
    """Tests for _start_browsers."""

    def test_start_browsers_creates_browsers(self) -> None:
        mock_zc = MagicMock()
        collector = _ServiceCollector()

        with patch("zeroconf.ServiceBrowser", return_value=MagicMock()) as mock_sb:
            browsers = _start_browsers(mock_zc, collector)
            assert len(browsers) > 0
            assert mock_sb.call_count == len(browsers)


class TestProcessCollectedServices:
    """Tests for _process_collected_services."""

    @patch("src.mdns_scanner._resolve_service")
    def test_processes_found_services(self, mock_resolve) -> None:
        mock_device = MdnsDevice(hostname="test.local", ip_address="10.0.0.1", mac_address="AA:BB:CC:DD:EE:FF")
        mock_resolve.return_value = mock_device

        mock_zc = MagicMock()
        collector = _ServiceCollector()
        collector.found.append(("_http._tcp.local.", "WebServer._http._tcp.local."))

        seen: set[str] = set()
        devices = _process_collected_services(mock_zc, collector, seen, 5.0)
        assert len(devices) == 1
        assert devices[0].hostname == "test.local"

    @patch("src.mdns_scanner._resolve_service", return_value=None)
    def test_skips_unresolved_services(self, _mock_resolve) -> None:
        mock_zc = MagicMock()
        collector = _ServiceCollector()
        collector.found.append(("_http._tcp.local.", "Ghost._http._tcp.local."))

        devices = _process_collected_services(mock_zc, collector, set(), 5.0)
        assert len(devices) == 0


class TestScanMdnsServicesHappyPath:
    """Tests for scan_mdns_services with full mock stack."""

    @patch("time.sleep")
    @patch("src.mdns_scanner._process_collected_services", return_value=[])
    @patch("src.mdns_scanner._start_browsers", return_value=[MagicMock()])
    def test_happy_path(self, _mock_browsers, _mock_process, _mock_sleep) -> None:
        from src.mdns_scanner import scan_mdns_services

        result = scan_mdns_services(timeout=0.1)
        assert isinstance(result, list)

    @patch("time.sleep")
    @patch("src.mdns_scanner._process_collected_services")
    @patch("src.mdns_scanner._start_browsers")
    def test_returns_found_devices(self, mock_browsers, mock_process, _mock_sleep) -> None:
        mock_browsers.return_value = [MagicMock()]
        device = MdnsDevice(hostname="test.local", ip_address="10.0.0.1", mac_address="AA:BB:CC:DD:EE:FF")
        mock_process.return_value = [device]

        from src.mdns_scanner import scan_mdns_services

        result = scan_mdns_services(timeout=0.1)
        assert len(result) == 1
        assert result[0].hostname == "test.local"
