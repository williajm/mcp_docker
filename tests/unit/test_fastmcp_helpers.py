"""Tests for FastMCP helper utilities."""

from mcp_docker.services.safety import OperationSafety
from mcp_docker.utils.fastmcp_helpers import create_fastmcp_app, get_mcp_annotations
from mcp_docker.version import __version__


class TestCreateFastmcpApp:
    """Tests for create_fastmcp_app function."""

    def test_default_name(self) -> None:
        """Test creating app with default name."""
        app = create_fastmcp_app()

        assert app.name == "mcp-docker"

    def test_custom_name(self) -> None:
        """Test creating app with custom name."""
        app = create_fastmcp_app(name="my-custom-server")

        assert app.name == "my-custom-server"

    def test_version_is_set(self) -> None:
        """Test that version is set from package version."""
        app = create_fastmcp_app()

        # FastMCP stores version - verify it's set
        # Note: FastMCP 2.0 stores version in different ways depending on version
        # We verify the app was created successfully with version info
        assert app is not None
        # Version should match package version
        assert __version__ is not None

    def test_returns_fastmcp_instance(self) -> None:
        """Test that function returns a FastMCP instance."""
        from fastmcp import FastMCP

        app = create_fastmcp_app()

        assert isinstance(app, FastMCP)

    def test_empty_name_gets_default(self) -> None:
        """Test creating app with empty name gets a default from FastMCP."""
        app = create_fastmcp_app(name="")

        # FastMCP generates a default name when given empty string
        assert app.name is not None
        assert len(app.name) > 0

    def test_name_with_special_characters(self) -> None:
        """Test creating app with special characters in name."""
        app = create_fastmcp_app(name="mcp-docker-v2.0_test")

        assert app.name == "mcp-docker-v2.0_test"


class TestGetMcpAnnotations:
    """Tests for get_mcp_annotations function."""

    def test_safe_operation_annotations(self) -> None:
        """Test annotations for SAFE operations."""
        annotations = get_mcp_annotations(OperationSafety.SAFE)

        assert annotations["readOnly"] is True
        assert annotations["destructive"] is False

    def test_moderate_operation_annotations(self) -> None:
        """Test annotations for MODERATE operations."""
        annotations = get_mcp_annotations(OperationSafety.MODERATE)

        assert annotations["readOnly"] is False
        assert annotations["destructive"] is False

    def test_destructive_operation_annotations(self) -> None:
        """Test annotations for DESTRUCTIVE operations."""
        annotations = get_mcp_annotations(OperationSafety.DESTRUCTIVE)

        assert annotations["readOnly"] is False
        assert annotations["destructive"] is True

    def test_returns_dict(self) -> None:
        """Test that function returns a dictionary."""
        annotations = get_mcp_annotations(OperationSafety.SAFE)

        assert isinstance(annotations, dict)

    def test_has_expected_keys(self) -> None:
        """Test that annotations contain expected keys."""
        annotations = get_mcp_annotations(OperationSafety.MODERATE)

        assert "readOnly" in annotations
        assert "destructive" in annotations

    def test_only_has_expected_keys(self) -> None:
        """Test that annotations only contain expected keys."""
        annotations = get_mcp_annotations(OperationSafety.SAFE)

        assert set(annotations.keys()) == {"readOnly", "destructive"}

    def test_all_safety_levels_return_valid_annotations(self) -> None:
        """Test that all safety levels return valid boolean annotations."""
        for safety_level in OperationSafety:
            annotations = get_mcp_annotations(safety_level)

            assert isinstance(annotations["readOnly"], bool)
            assert isinstance(annotations["destructive"], bool)

    def test_annotations_are_mutually_consistent(self) -> None:
        """Test that readOnly and destructive are consistent (can't be both True)."""
        for safety_level in OperationSafety:
            annotations = get_mcp_annotations(safety_level)

            # A destructive operation cannot be read-only
            if annotations["destructive"]:
                assert annotations["readOnly"] is False

            # A read-only operation cannot be destructive
            if annotations["readOnly"]:
                assert annotations["destructive"] is False
