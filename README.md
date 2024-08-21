# 69ll Phisher Protector
96switch
import hashlib
import logging
import re

# Logger configuration
logging.basicConfig(filename='protector.log', level=logging.INFO)

# Known phishing prompts
phishing_prompts = [
    "Hello world!",
    "Please enter your sensitive information",
    "Then you will be asked to enter the most sensitive information"
]

# Regular expression pattern to detect phishing prompts
pattern = re.compile(r"|".join(re.escape(prompt) for prompt in phishing_prompts), re.IGNORECASE)

# Input validator
def validate_input(input_text):
    """Validate user input against known phishing prompts"""
    if pattern.search(input_text):
        logging.warning("Phishing attempt detected!")
        return False
    return True

# Hash generator
def generate_hash(input_text):
    """Generate a hash of the user input"""
    return hashlib.sha256(input_text.encode()).hexdigest()

# Main program
def main():
    input_text = input("Enter your sensitive information: ")

    if validate_input(input_text):
        hashed_input = generate_hash(input_text)
        logging.info("Input validated and hashed: {}".format(hashed_input))
        print("Your input has been securely processed.")
    else:
        logging.warning("Phishing attempt blocked!")

if __name__ == "__main__":
    main()
