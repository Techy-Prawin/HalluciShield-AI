import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
from app.agents.sandbox_agent import SandboxAgent
import docker

agent = SandboxAgent()
docker_client = agent._docker

# Check if image exists
try:
    images = docker_client.images.list()
    matching = [img for img in images if agent.image_name in img.tags]
    print('Image found:', len(matching))
    for img in matching:
        print('  ', img.tags)
except docker.errors.DockerException as e:
    print('Docker error getting images:', e)

# Try to ping Docker
try:
    docker_client.ping()
    print('Docker ping: OK')
except docker.errors.DockerException as e:
    print('Docker ping failed:', e)

# Try to list containers
try:
    containers = docker_client.containers.list(all=True)
    print('Containers listed:', len(containers))
except docker.errors.DockerException as e:
    print('Docker containers error:', e)