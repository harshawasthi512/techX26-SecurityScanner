#!/usr/bin/env python3
import os
from dotenv import load_dotenv

def setup_environment():
    """Setup environment variables"""
    if not os.path.exists(".env"):
        print("Creating .env file...")
        with open(".env", "w") as f:
            f.write("""# GitHub Personal Access Token (optional but recommended)
# Get one from: https://github.com/settings/tokens
# No special permissions needed for public repos
GITHUB_TOKEN=your_github_token_here

# Optional: Scan configuration
# MAX_CONCURRENT_CLONES=3
MAX_FILE_SIZE_MB=5
SKIP_EXTENSIONS=.exe,.dll,.so,.dylib,.jpg,.png,.gif,.pdf,.zip,.tar.gz,.tgz,.mp4,.avi,.mov

# Server configuration
PORT=8000
""")
        print("\nPlease edit the .env file and add your GitHub token.")
        print("You can get a token from: https://github.com/settings/tokens")
    else:
        print(".env file already exists")
    
    # Check if requirements are installed
    print("\nChecking requirements...")
    try:
        import fastapi
        import uvicorn
        import gitpython
        print("✓ All requirements are installed")
    except ImportError as e:
        print(f"✗ Missing requirement: {e}")
        print("Run: pip install -r requirements.txt")

if __name__ == "__main__":
    setup_environment()