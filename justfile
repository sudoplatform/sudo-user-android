# justfile for generic command runner

renovate-post:
    # Ensure the script is executable
    chmod +x util/post-renovate.sh
    # Execute the post-renovate script
    bash util/post-renovate.sh
