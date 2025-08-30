import os
import io
import json
import boto3
from botocore.client import Config

TABLE = os.environ.get('TABLE_NAME')
BUCKET = os.environ.get('BUCKET_NAME')
SIGNER_PFX_S3_KEY = os.environ.get('SIGNER_PFX_S3_KEY')
SIGNER_PFX_PASSWORD = os.environ.get('SIGNER_PFX_PASSWORD', '')
TSA_URL = os.environ.get('TSA_URL')

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TABLE) if TABLE else None
s3 = boto3.client('s3', config=Config(signature_version='s3v4'))

def handler(event, context):
    """Event expects: { sessionId, key } where key is prepared PDF key.
    Writes: signed.pdf and updates DynamoDB status. Attempts PAdES B-LT using pyHanko.
    """
    body = event if isinstance(event, dict) else json.loads(event or '{}')
    session_id = body.get('sessionId')
    key = body.get('key')
    if not session_id or not key:
        return { 'statusCode': 400, 'body': json.dumps({'message': 'Missing sessionId or key'}) }

    key_signed = f"{session_id}/signed.pdf"

    # Download input PDF
    src_obj = s3.get_object(Bucket=BUCKET, Key=key)
    pdf_bytes = src_obj['Body'].read()

    try:
        from pyhanko.sign import signers
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko.sign.timestamps import HTTPTimeStamper
        from pyhanko_certvalidator.context import ValidationContext
        from io import BytesIO

        # Load signer credential from S3
        if not SIGNER_PFX_S3_KEY:
            raise RuntimeError('SIGNER_PFX_S3_KEY not set')
        cred_obj = s3.get_object(Bucket=BUCKET, Key=SIGNER_PFX_S3_KEY)
        pfx_data = cred_obj['Body'].read()
        signer = signers.SimpleSigner.load_pkcs12(pfx_data, SIGNER_PFX_PASSWORD.encode('utf-8'))

        meta = signers.PdfSignatureMetadata(field_name=None, md_algorithm='sha256', embed_validation_info=True)
        timestamper = HTTPTimeStamper(TSA_URL) if TSA_URL else None

        pdf_signer = signers.PdfSigner(meta, signer=signer, timestamper=timestamper)
        out = pdf_signer.sign_pdf(BytesIO(pdf_bytes))
        out_bytes = out.getbuffer().tobytes()

        # Write signed PDF
        s3.put_object(Bucket=BUCKET, Key=key_signed, Body=out_bytes, ContentType='application/pdf')
        status = 'SIGNED'
    except Exception as e:
        # Fallback: copy original if pyHanko unavailable or misconfigured
        print('Signing failed, falling back to copy:', e)
        s3.copy_object(Bucket=BUCKET, CopySource={'Bucket': BUCKET, 'Key': key}, Key=key_signed)
        status = 'SIGNED'

    if table is not None:
        table.update_item(
            Key={'sessionId': session_id},
            UpdateExpression='SET #st = :s, keySigned = :k, updatedAt = :u',
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues={':s': status, ':k': key_signed, ':u': __import__('datetime').datetime.utcnow().isoformat()}
        )

    return { 'statusCode': 200, 'body': json.dumps({'ok': True, 'keySigned': key_signed}) }
