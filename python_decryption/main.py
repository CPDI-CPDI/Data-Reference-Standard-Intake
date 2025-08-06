import os
import csv
import base64
import json
from gc_forms_api_client import GCFormsApiClient
from form_submission_decrypter import FormSubmissionDecrypter
from form_submission_integrity_verifier import FormSubmissionVerifier
from access_token_generator import AccessTokenGenerator
from data_structures import PrivateApiKey, FormSubmission

IDENTITY_PROVIDER_URL = "https://auth.forms-formulaires.alpha.canada.ca"
PROJECT_IDENTIFIER = "284778202772022819"
GCFORMS_API_URL = "https://api.forms-formulaires.alpha.canada.ca"
CSV_FILENAME = "responses.csv"

def load_private_api_key() -> PrivateApiKey:
    try:
        encoded_key = os.environ.get("PRIVATE_KEY_B64")
        if not encoded_key:
            raise Exception("Environment variable PRIVATE_KEY_B64 not found")

        decoded_bytes = base64.b64decode(encoded_key)
        file_as_json_object = json.loads(decoded_bytes.decode("utf-8"))
        return PrivateApiKey.from_json(file_as_json_object)
    except Exception as exception:
        raise Exception("Failed to load private API key from environment") from exception

def get_existing_submission_ids(csv_filename):
    if not os.path.exists(csv_filename):
        return set()
    with open(csv_filename, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        return {row['submissionId'] for row in reader}

def write_submissions_to_csv(submissions, csv_filename):
    file_exists = os.path.exists(csv_filename)
    existing_ids = get_existing_submission_ids(csv_filename)

    with open(csv_filename, mode='a' if file_exists else 'w', newline='', encoding='utf-8') as file:
        fieldnames = ['submissionId', 'createdAt', 'confirmationCode', 'answers', 'checksum']
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        for submission in submissions:
            if submission.confirmation_code and submission.answers and submission.checksum:
                if submission.confirmation_code not in existing_ids:
                    writer.writerow({
                        'submissionId': submission.confirmation_code,
                        'createdAt': submission.created_at,
                        'confirmationCode': submission.confirmation_code,
                        'answers': submission.answers,
                        'checksum': submission.checksum
                    })

def main():
    private_api_key = load_private_api_key()
    access_token = AccessTokenGenerator.generate(
        IDENTITY_PROVIDER_URL, PROJECT_IDENTIFIER, private_api_key
    )
    api_client = GCFormsApiClient(
        private_api_key.form_id, GCFORMS_API_URL, access_token
    )

    new_form_submissions = api_client.get_new_form_submissions()
    if not new_form_submissions:
        print("No new submissions found.")
        return

    verified_submissions = []
    for new_submission in new_form_submissions:
        encrypted_submission = api_client.get_form_submission(new_submission.name)
        decrypted_json = FormSubmissionDecrypter.decrypt(encrypted_submission, private_api_key)
        form_submission = FormSubmission.from_json(json.loads(decrypted_json))

        if FormSubmissionVerifier.verify_integrity(form_submission.answers, form_submission.checksum):
            verified_submissions.append(form_submission)
            api_client.confirm_form_submission(new_submission.name, form_submission.confirmation_code)

    write_submissions_to_csv(verified_submissions, CSV_FILENAME)
    print(f"{len(verified_submissions)} new verified submissions saved to {CSV_FILENAME}.")

if __name__ == "__main__":
    main()
