# src/convert/Dockerfile
FROM public.ecr.aws/shelf/lambda-libreoffice-base:7.6-python3.12-x86_64

ENV HOME=/tmp

# Install JRE for LibreOffice
RUN dnf install -y java-17-amazon-corretto-headless && dnf clean all

# Copy code & deps
COPY app.py requirements.txt ${LAMBDA_TASK_ROOT}/
RUN python -m pip install -r ${LAMBDA_TASK_ROOT}/requirements.txt

CMD [ "app.handler" ]