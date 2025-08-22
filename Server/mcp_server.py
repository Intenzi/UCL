# mcp_server.py
import json
import logging
from typing import Optional
from urllib.parse import unquote  # To decode URL path components

# Use the official MCP library
from mcp.server.fastmcp import FastMCP

# Import the manager instance
from codebase_manager import manager

# Configure logging for the server
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

# Create the MCP server instance
mcp = FastMCP(
    name="Codebase Explorer",
    # version="0.1.0",
    # description="MCP Server to explore codebases using UCL indexing."
)
# --- MCP Resources ---


@mcp.resource("codebase://info")
def get_codebase_info() -> dict | None:
    """
    Provides information about the currently indexed codebase root.
    """
    log.debug("Received request for codebase://info")
    root = manager.get_codebase_root()
    if root:
        return {"codebase_root": str(root)}
    return None


@mcp.resource("codebase://structure")
def get_codebase_structure() -> dict | None:
    """
    Provides the hierarchical file tree structure of the indexed codebase.
    """
    log.debug("Received request for codebase://structure")
    return manager.get_file_tree()


@mcp.resource("codebase://files")
def list_parsed_files() -> list[str] | None:
    """
    Lists the relative paths of all files successfully parsed by UCLGenerator.
    """
    log.debug("Received request for codebase://files")
    return manager.get_parsed_files_list()


# --- MCP Tools ---

@mcp.tool()
def get_codebase_ucl() -> dict | None:
    """
    Retrieves the structured understanding of the last indexed codebase.
    Always call this after `index_codebase` to actually work with the codebase.
    This is the primary entry point to explore the codebase at scale.
    """
    log.debug("Received request for codebase://ucl")
    return manager.get_ucl_data()


@mcp.tool()
def get_file_ucl(relative_path: str) -> dict | None:
    """
    Provides the structured UCL data (imports, classes, functions, lines)
    for a specific parsed file.
    Use URL encoding for the relative_path if it contains special characters.
    """
    # The :path converter captures everything, including slashes.
    # Decode potential URL encoding in the path segment.
    decoded_path = unquote(relative_path)
    log.info(f"Received request for codebase://ucl/{decoded_path}")
    log.info(manager.ucl_data)
    return manager.get_parsed_file_ucl(decoded_path)


@mcp.tool()
async def index_local_codebase(path: str) -> str:
    """
    Indexes a codebase located on the local filesystem.
    Provide the absolute path to the codebase directory.
    Returns a status message.
    """
    log.info(f"Received tool call: index_local_codebase with path: {path}")
    success, message = await manager.index_local_codebase(path)
    return message


@mcp.tool()
async def index_github_codebase(url: str) -> str:
    """
    Clones and indexes a codebase from a GitHub repository URL.
    Example: https://github.com/user/repo.git
    Returns a status message.
    After calling this, you MUST use `get_codebase_ucl` to fetch structured context.
    """
    log.info(f"Received tool call: index_github_codebase with url: {url}")
    success, message = await manager.index_github_codebase(url)
    return message


@mcp.tool()
def get_file_lines(relative_file_path: str, start_line: Optional[int] = None, end_line: Optional[int] = None) -> str:
    """
    Fetches specific lines (or the entire content) of a source file
    within the currently indexed codebase.
    relative_file_path should be the path relative to the codebase root,
    using forward slashes (e.g., 'src/my_module/file.py').
    start_line and end_line are 1-based inclusive line numbers.
    Returns the file content or an error message.

    After calling this, you MUST use `get_codebase_ucl` to fetch structured context.
    """
    log.info(f"Received tool call: get_file_lines for '{relative_file_path}', lines {start_line}-{end_line}")
    # Decode just in case, though tool arguments might be handled differently than URL paths
    decoded_path = unquote(relative_file_path)
    content, message = manager.get_file_source_lines(decoded_path, start_line, end_line)
    log.debug(f"get_file_lines result message: {message}")
    if content is None:
        return f"Error: {message}"  # Return error message if content is None
    return content  # Return the actual content string on success

# --- Running the Server (Example) ---
# You can run this using: uvicorn mcp_server:mcp.app --reload
# Or using the mcp CLI: mcp dev mcp_server.py


if __name__ == "__main__":
    try:
        # log.info("Starting MCP server on http://127.0.0.1:8000")
        mcp.run()
    except Exception as e:
        log.error(f"Failed to run server: {e}", exc_info=True)
