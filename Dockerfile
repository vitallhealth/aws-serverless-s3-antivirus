FROM public.ecr.aws/lambda/python:3.11

RUN yum clean all
RUN yum update -y
RUN python -m pip install --upgrade pip
RUN yum install amazon-linux-extras -y
# Python3 doesn't recognize this package yet. https://forums.aws.amazon.com/thread.jspa?messageID=930259
RUN PYTHON=python2 amazon-linux-extras install epel -y

# Install ClamAV
RUN yum install -y clamav clamav-update && \
    yum clean all
# Force running freshclam everytime the image is being built, so new antivirus definitions are downloaded
ARG CACHEBUST=1
RUN echo $CACHEBUST
RUN freshclam

# Install Ghostscript
RUN yum install -y ghostscript wget unzip

# Install pdfid
RUN wget https://didierstevens.com/files/software/pdfid_v0_2_10.zip \
    && unzip pdfid_v0_2_10.zip -d /opt/pdfid \
    && chmod +x /opt/pdfid/pdfid.py

COPY function/virus-scanner.py ${LAMBDA_TASK_ROOT}/
COPY clamd.conf /etc/clamd.conf
COPY ./requirements.txt ${LAMBDA_TASK_ROOT}/requirements.txt

RUN cd ${LAMBDA_TASK_ROOT}
RUN pip install -r ${LAMBDA_TASK_ROOT}/requirements.txt -t .

CMD [ "virus-scanner.lambda_handler" ]