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
CSV_FILENAME = "python_decryption/responses.csv"
RAW_TXT_FILENAME = "python_decryption/responses.txt"

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

def write_submissions_to_csv(submissions, csv_filename):
    file_exists = os.path.exists(csv_filename)

    with open(csv_filename, mode='a' if file_exists else 'w', newline='', encoding='utf-8') as file:
        fieldnames = ['submissionId', 'createdAt', 'confirmationCode', 'answers', 'checksum']
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        for submission in submissions:
            if submission.confirmation_code and submission.answers and submission.checksum:
                writer.writerow({
                    'submissionId': submission.confirmation_code,
                    'createdAt': submission.created_at,
                    'confirmationCode': submission.confirmation_code,
                    'answers': json.dumps(submission.answers),
                    'checksum': submission.checksum
                })

def write_raw_text_objects(raw_objects, raw_txt_filename):
    with open(raw_txt_filename, 'w', encoding='utf-8') as f:
        for i, obj in enumerate(raw_objects):
            f.write(f"--- Submission {i + 1} ---\n")
            try:
                if isinstance(obj, str):
                    f.write(obj + "\n\n")
                elif hasattr(obj, "to_json"):
                    f.write(json.dumps(obj.to_json(), indent=2) + "\n\n")
                elif hasattr(obj, "__dict__"):
                    f.write(json.dumps(obj.__dict__, indent=2) + "\n\n")
                else:
                    f.write(str(obj) + "\n\n")
            except Exception as e:
                f.write(f"[Error serializing submission {i + 1}]: {e}\n\n")

def main():
    private_api_key = load_private_api_key()
    responses_for_file = ""
    print("\nGenerating access token...")

    access_token = AccessTokenGenerator.generate(
        IDENTITY_PROVIDER_URL, PROJECT_IDENTIFIER, private_api_key
    )

    api_client = GCFormsApiClient(
        private_api_key.form_id, GCFORMS_API_URL, access_token
    )

    print("\nRetrieving form template...\n")

    form_template = api_client.get_form_template()

    print(form_template)

    print("\nRetrieving new form submissions...")

    new_form_submissions = api_client.get_new_form_submissions()

    if len(new_form_submissions) > 0:
        print("\nNew form submissions:")

        print(", ".join(x.name for x in new_form_submissions))

        print("\nRetrieving, decrypting and confirming form submissions...")

        for new_form_submission in new_form_submissions:
            print(f"\nProcessing {new_form_submission.name}...\n")

            print("Retrieving encrypted submission...")

            encrypted_submission = api_client.get_form_submission(
                new_form_submission.name
            )

            print("\nEncrypted submission:")
            print(encrypted_submission.encrypted_responses)

            print("\nDecrypting submission...")

            decrypted_form_submission = FormSubmissionDecrypter.decrypt(
                encrypted_submission, private_api_key
            )

            print("\nDecrypted submission:")
            print(decrypted_form_submission)

            form_submission = FormSubmission.from_json(
                json.loads(decrypted_form_submission)
            )

            print("\nVerifying submission integrity...")

            integrity_verification_result = FormSubmissionVerifier.verify_integrity(
                form_submission.answers, form_submission.checksum
            )

            print(
                f"\nIntegrity verification result: {'OK' if integrity_verification_result else 'INVALID'}"
            )

            print("\nConfirming submission...")

            api_client.confirm_form_submission(
                new_form_submission.name, form_submission.confirmation_code
            )

            print("\nSubmission confirmed")
            
            print(form_submission["answers"]["1"])

            responses_for_file = responses_for_file + decrypted_form_submission
    else:
        print("\nCould not find any new form submission!")

    write_raw_text_objects(responses_for_file, RAW_TXT_FILENAME)

    print(f"Raw encrypted responses saved to {RAW_TXT_FILENAME}.")

if __name__ == "__main__":
    main()


