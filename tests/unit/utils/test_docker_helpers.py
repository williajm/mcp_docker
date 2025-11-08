"""Unit tests for Docker API helper utilities."""

from typing import Any

from mcp_docker.utils.docker_helpers import safe_get_dict, safe_get_list, safe_get_str


class TestSafeGetList:
    """Tests for safe_get_list function."""

    def test_get_existing_list(self) -> None:
        """Test retrieving existing list value."""
        data = {"Env": ["PATH=/usr/bin", "HOME=/root"]}
        result = safe_get_list(data, "Env")
        assert result == ["PATH=/usr/bin", "HOME=/root"]

    def test_get_none_returns_empty_list(self) -> None:
        """Test that None value returns empty list."""
        data = {"Env": None}
        result = safe_get_list(data, "Env")
        assert result == []

    def test_get_missing_key_returns_empty_list(self) -> None:
        """Test that missing key returns empty list."""
        data: dict[str, Any] = {}
        result = safe_get_list(data, "Env")
        assert result == []

    def test_get_nested_list(self) -> None:
        """Test retrieving nested list value."""
        data = {"Config": {"Env": ["VAR1=value1", "VAR2=value2"]}}
        result = safe_get_list(data, "Config", "Env")
        assert result == ["VAR1=value1", "VAR2=value2"]

    def test_get_nested_with_none_intermediate(self) -> None:
        """Test handling None in path traversal."""
        data = {"Config": None}
        result = safe_get_list(data, "Config", "Env")
        assert result == []

    def test_get_non_list_value_returns_empty_list(self) -> None:
        """Test that non-list value returns empty list."""
        data = {"Env": "not-a-list"}
        result = safe_get_list(data, "Env")
        assert result == []

    def test_empty_list_returned_as_is(self) -> None:
        """Test that empty list is returned unchanged."""
        data: dict[str, Any] = {"Env": []}
        result = safe_get_list(data, "Env")
        assert result == []


class TestSafeGetDict:
    """Tests for safe_get_dict function."""

    def test_get_existing_dict(self) -> None:
        """Test retrieving existing dict value."""
        data = {"NetworkSettings": {"Ports": {"80/tcp": [{"HostPort": "8080"}]}}}
        result = safe_get_dict(data, "NetworkSettings", "Ports")
        assert result == {"80/tcp": [{"HostPort": "8080"}]}

    def test_get_none_returns_empty_dict(self) -> None:
        """Test that None value returns empty dict."""
        data = {"NetworkSettings": {"Ports": None}}
        result = safe_get_dict(data, "NetworkSettings", "Ports")
        assert result == {}

    def test_get_missing_key_returns_empty_dict(self) -> None:
        """Test that missing key returns empty dict."""
        data: dict[str, Any] = {}
        result = safe_get_dict(data, "NetworkSettings", "Ports")
        assert result == {}

    def test_get_single_level_dict(self) -> None:
        """Test retrieving single-level dict."""
        data = {"Config": {"Image": "nginx", "Cmd": ["nginx"]}}
        result = safe_get_dict(data, "Config")
        assert result == {"Image": "nginx", "Cmd": ["nginx"]}

    def test_get_nested_with_none_intermediate(self) -> None:
        """Test handling None in path traversal."""
        data = {"NetworkSettings": None}
        result = safe_get_dict(data, "NetworkSettings", "Ports")
        assert result == {}

    def test_get_non_dict_value_returns_empty_dict(self) -> None:
        """Test that non-dict value returns empty dict."""
        data = {"Config": "not-a-dict"}
        result = safe_get_dict(data, "Config")
        assert result == {}

    def test_empty_dict_returned_as_is(self) -> None:
        """Test that empty dict is returned unchanged."""
        data: dict[str, Any] = {"Config": {}}
        result = safe_get_dict(data, "Config")
        assert result == {}


class TestSafeGetStr:
    """Tests for safe_get_str function."""

    def test_get_existing_string(self) -> None:
        """Test retrieving existing string value."""
        data = {"State": {"Status": "running"}}
        result = safe_get_str(data, "State", "Status")
        assert result == "running"

    def test_get_none_returns_default(self) -> None:
        """Test that None value returns default."""
        data = {"State": {"Status": None}}
        result = safe_get_str(data, "State", "Status", default="unknown")
        assert result == "unknown"

    def test_get_missing_key_returns_default(self) -> None:
        """Test that missing key returns default."""
        data: dict[str, Any] = {"State": {}}
        result = safe_get_str(data, "State", "Status", default="unknown")
        assert result == "unknown"

    def test_default_empty_string(self) -> None:
        """Test that default is empty string when not specified."""
        data: dict[str, Any] = {}
        result = safe_get_str(data, "State", "Status")
        assert result == ""

    def test_convert_int_to_string(self) -> None:
        """Test that integer value is converted to string."""
        data = {"State": {"ExitCode": 0}}
        result = safe_get_str(data, "State", "ExitCode")
        assert result == "0"

    def test_nested_with_none_intermediate(self) -> None:
        """Test handling None in path traversal."""
        data = {"State": None}
        result = safe_get_str(data, "State", "Status", default="N/A")
        assert result == "N/A"


class TestDockerAPIRealWorldScenarios:
    """Test real-world Docker API response scenarios."""

    def test_minimal_container_with_null_env(self) -> None:
        """Test handling minimal container with Env: null."""
        container_attrs: dict[str, Any] = {
            "Config": {"Image": "alpine", "Env": None},
            "HostConfig": {"Binds": None},
        }
        config = container_attrs["Config"]
        host_config = container_attrs["HostConfig"]
        assert isinstance(config, dict)
        assert isinstance(host_config, dict)
        env = safe_get_list(config, "Env")
        binds = safe_get_list(host_config, "Binds")

        assert env == []
        assert binds == []

    def test_container_with_missing_network_settings(self) -> None:
        """Test handling container without NetworkSettings."""
        container_attrs: dict[str, Any] = {"Config": {}}
        ports = safe_get_dict(container_attrs, "NetworkSettings", "Ports")

        assert ports == {}

    def test_restart_policy_extraction(self) -> None:
        """Test safe extraction of restart policy name."""
        host_config = {"RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0}}
        restart_policy = safe_get_dict(host_config, "RestartPolicy").get("Name", "no")

        assert restart_policy == "unless-stopped"

    def test_restart_policy_null(self) -> None:
        """Test handling null restart policy."""
        host_config = {"RestartPolicy": None}
        restart_policy = safe_get_dict(host_config, "RestartPolicy").get("Name", "no")

        assert restart_policy == "no"

    def test_restart_policy_missing(self) -> None:
        """Test handling missing restart policy."""
        host_config: dict[str, Any] = {}
        restart_policy = safe_get_dict(host_config, "RestartPolicy").get("Name", "no")

        assert restart_policy == "no"
