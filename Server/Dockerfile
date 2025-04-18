# Server/Dockerfile

# Use an official Python runtime as a parent image
FROM python:3.8

# Set environment variables
ENV PYTHONUNBUFFERED True  # Ensures print statements appear without delay
ENV APP_HOME /app          # Define the application directory in the container
ENV PORT 8080              # Define the port the app will run on (Cloud Run injects PORT env var)

WORKDIR $APP_HOME          # Set the working directory in the container

# downloading git cmdline tool for gitpython
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    # Clean up apt cache to keep image size down
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy local code (from the Server directory context) to the container image
COPY . ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run the application using Gunicorn
# It looks for the 'app' variable in the 'server.py' file (server:app)
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 uclserver:app