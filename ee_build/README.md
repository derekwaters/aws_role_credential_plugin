1. Building the EE

'''
ansible-builder build -t localhost/aws-ee-with-env
'''

2. Run the local image server

'''
podman run -d -p 5000:5000 --name registry registry
'''

3. Tag your local image with the "remote" repo

'''
podman image tag localhost/aws-ee-with-env localhost:5000/aws-ee-with-env
'''

4. Push the image

'''
podman push localhost:5000/aws-ee-with-env
'''

5. Now import the image as an EE into AAP
