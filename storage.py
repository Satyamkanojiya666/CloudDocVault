"""Storage as a Service: AWS S3 in the cloud, local folder for development."""
import os
import io


class LocalStorage:
    kind = "Local disk"

    def __init__(self, folder):
        self.folder = folder
        os.makedirs(folder, exist_ok=True)

    def save(self, fileobj, key):
        with open(os.path.join(self.folder, key), "wb") as f:
            f.write(fileobj.read())

    def load(self, key):
        with open(os.path.join(self.folder, key), "rb") as f:
            return io.BytesIO(f.read())

    def delete(self, key):
        try:
            os.remove(os.path.join(self.folder, key))
        except FileNotFoundError:
            pass

    def ping(self):
        return os.access(self.folder, os.W_OK)


class S3Storage:
    kind = "AWS S3"

    def __init__(self, bucket, region):
        import boto3  # lazy import
        # Credentials come from the EC2/Beanstalk IAM role - never hard-coded.
        self.s3 = boto3.client("s3", region_name=region)
        self.bucket = bucket

    def save(self, fileobj, key):
        self.s3.upload_fileobj(fileobj, self.bucket, key,
                               ExtraArgs={"ServerSideEncryption": "AES256"})

    def load(self, key):
        buf = io.BytesIO()
        self.s3.download_fileobj(self.bucket, key, buf)
        buf.seek(0)
        return buf

    def delete(self, key):
        self.s3.delete_object(Bucket=self.bucket, Key=key)

    def ping(self):
        self.s3.head_bucket(Bucket=self.bucket)
        return True


def get_storage(base_dir):
    bucket = os.environ.get("S3_BUCKET", "").strip()
    if bucket:
        return S3Storage(bucket, os.environ.get("AWS_REGION", "ap-south-1"))
    return LocalStorage(os.path.join(base_dir, "uploads"))
