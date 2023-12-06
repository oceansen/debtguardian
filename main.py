"""
Project: Technical and Security Debt Analysis in GitHub Repositories
Program name: DebtGuardianAI.ipynb
Author: Sagar Sen
Date created: 19-10-2023
Revision history:
23-10-2023 Updated prompt to be more precise about only including security debts if they exist in the response
Purpose: Analyzing security debt in commits within GitHub repositories to identify potential vulnerabilities and technical debt leading to security issues.
Copyright: (c) 2023 Sagar Sen. All rights reserved.
Notes: This program analyzes commits in GitHub repositories to identify patterns that might indicate security debt. The analysis includes checking for hard-coded credentials, use of outdated libraries, and other common security debt indicators.
Contact: sagar.sen@sintef.no
"""

"""
Pre-requisities
!pip install pydriller
!pip install requests
!pip install openai==0.28.1
!pip install pygments
!pip install pydantic==1.10.9
!apt-get install -y graphviz openjdk-11-jre-headless
!pip install guardrails-ai  typing  rich
!pip install tiktoken
"""

import textwrap
from pygments.lexers import get_lexer_by_name
from pygments.util import ClassNotFound
import os
import openai
from pydriller import Repository
import time
import re
from pydantic import BaseModel, Field
from typing import List, Optional
from guardrails.validators import ValidRange, ValidChoices
from rich import print
import guardrails as gd
import argparse
import json
import os

#Setup openai
engineName="jaipetefort"
openai.api_type = "azure"
openai.api_base = "https://03.openai.azure.com/"
openai.api_version = "2023-07-01-preview"
# Read API key from environment variable
openai.api_key = os.getenv('OPENAI_API_KEY')

if not openai.api_key:
    raise ValueError("No API key found. Please set the OPENAI_API_KEY environment variable.")





#Helper Functions

def call_openai_api(messages, retries=3):
    for _ in range(retries):
        try:
            response = openai.ChatCompletion.create(
                engine=engineName,
                messages=messages,
                temperature=0.7,
                max_tokens=500,
                top_p=0.95,
                frequency_penalty=0,
                presence_penalty=0,
                stop=None
            )
            return response
        except openai.error.InvalidRequestError as e:
            # Specifically handle the token limit error
            if "Maximum context length" in str(e) and "tokens" in str(e):
                print("Error: Message length exceeds the model's token limit. Please reduce the length of the messages.")
                # You might want to break here, as reducing the message length requires user intervention.
                break
        except Exception as e:
            error=(f"Error: {e}.")
            print(wrap_text(error))
            #print(f"Error: {e}.")
            match = re.search(r'(\d+)\s+seconds?', str(e))
            if match:
              seconds = int(match.group(1))
              print(seconds)
            else:
              print("Seconds not found in the text!")
            print("Retrying calling AI engine in "+str(seconds)+" seconds...")
            time.sleep(seconds)
        else:
            raise Exception("Failed to call OpenAI API after multiple retries.")
        


"""
Technical and Security Debts Schema
"""


class TechnicalDebt(BaseModel):
    type: str = Field(
    description="What type of technical debt is identified in this code snippet?",
    validators=[
        ValidChoices(
            choices=[
                'Code Duplication',
                'Complex Code',
                'Long Methods',
                'Poorly Named Classes/Methods',
                'Lack of Modularity',
                'Insufficient Testing',
                'Outdated Documentation',
                'Lack of Coding Standards',
                'Hard-coded Values',
                'Deprecated Dependencies',
                'Ignoring Refactoring',
                'Error/Exception Handling',
                'Inefficient Resource Management',
                'Lack of Concurrency Control'
            ],
            on_fail="reask"
        )
    ])
    symptom: str = Field(description="Technical debt in the code snippet.")
    affected_area: str= Field(description="What are the lines of code with the technical debt?")
    suggested_repair: str= Field(description="Generate code to refactor or repair the technical debt")


class SecurityDebt(BaseModel):
    type: str = Field(
    description="What is the security debt in this code snippet?",
    validators=[
        ValidChoices(
            choices=[
                'Hardcoded Secrets',
                'Insecure Dependencies',
                'Lack of Input Validation',
                'Insufficient Error Handling',
                'Inadequate Encryption',
                'Improper Session Management',
                'Insecure Default Settings',
                'Lack of Principle of Least Privilege',
                'Insecure Direct Object References',
                'Cross-Site Request Forgery (CSRF)',
                'Ignoring Security Warnings',
                'Not Adhering to Secure Coding Standards'
            ],
            on_fail="reask"
        )
    ])
    symptom: str = Field(description="Security debt in the code snippet.")
    affected_area: str= Field(description="What are the lines of code with the security debt?")
    suggested_repair: str= Field(description="Generate code to refactor or repair the security debt")



class CodeInfo(BaseModel):
    """
    A model representing various aspects of a code snippet, including its functionality, size, and associated debts.

    This class is designed to encapsulate information about a code snippet, such as its purpose, the number of lines it contains,
    and any identified technical or security debts. It uses the Pydantic library for data validation and settings management.

    Attributes:
    - snippet_functionality (str): Describes the functionality of the code snippet.
    - number_of_lines (int): Indicates the total number of lines in the code snippet.
    - securityDebts (List[SecurityDebt]): A list of identified security debts in the code snippet. Each security debt is an instance of the SecurityDebt class.
    - technicalDebts (List[TechnicalDebt]): A list of identified technical debts in the code snippet. Each technical debt is an instance of the TechnicalDebt class.
    """
    snippet_functionality: str = Field(description="What is the functionality of this code snippet?")
    number_of_lines: int = Field(description="What is the number of lines of code in this code snippet?")
    securityDebts: List[SecurityDebt] = Field(description="Are there security debts in the code snippet? Each security debt should be classified into  separate item in the list.")
    technicalDebts: List[TechnicalDebt] = Field(description="Are there technical debts in the code snippet? Each technical debt should be classified into  separate item in the list.")

def createGuard(code_changes):

  prompt = """
  Given the following code snippet, please extract a dictionary that contains the security vulnerabilities in the code. Validate if these vulnerabilities actually exist.

  ${code_changes} <!-- (2)! -->

  ${gr.complete_json_suffix_v2} <!-- (3)! -->
  """

  # From pydantic:
  guard = gd.Guard.from_pydantic(output_class=CodeInfo, prompt=prompt)

  #print(guard)

  return guard

def debtDetect(code_changes,guard):

  # Wrap the OpenAI API call with the `guard` object
  raw_llm_output, validated_output = guard(
    openai.ChatCompletion.create,
    prompt_params={"code_changes": code_changes},
    engine="jaipetefort",
    max_tokens=1024,
    temperature=0.3,
    )
  #print(validated_output)
  return validated_output


def is_source_code(filename):
    """
    Determine if a given filename corresponds to a source code file.

    This function checks the file extension against a predefined list of common
    source code file extensions. It's a simple way to guess if a file is a source code file.

    Args:
    - filename (str): The name of the file to check.

    Returns:
    - bool: True if the file extension matches a known source code extension, False otherwise.
    """
    # A basic list of source code extensions; can be expanded based on requirements
    source_code_extensions = [
        '.c', '.cpp', '.h', '.java', '.py', '.js', '.php',
        '.cs', '.rb', '.go', '.rs', '.ts', '.m', '.swift',
        '.f', '.f90', '.perl', '.sh', '.bash'
    ]

    # Extract the extension and check if it's in our list
    _, ext = os.path.splitext(filename)
    return ext in source_code_extensions



def print_bar(length=200, char='█'):
    """
    Print a horizontal bar with a given length and character.

    :param length: Length of the bar to be printed
    :param char: Character to use for printing the bar
    """
    print(char * length)

def wrap_text(text, width=200):
    """
    Wrap the given text to the specified width.

    :param text: Text to wrap
    :param width: Width at which to wrap the text
    :return: Wrapped text
    """
    return textwrap.fill(text, width)

def url_to_filename(url):
    # Replace invalid filename characters with an underscore
    filename = re.sub(r'[\\/*?"<>|:]', '_', url)
    return filename
#Main Function


# Main Function
def main(repo_url, resume=False):
    debts_file = url_to_filename(repo_url)+'_debts.json'
    debts = {}

    # Load existing debts if resume is True
    if resume and os.path.exists(debts_file):
        with open(debts_file, 'r') as file:
            debts = json.load(file)

    for commit in Repository(repo_url).traverse_commits():
        if commit.hash in debts and debts[commit.hash]:
            continue  # Skip if already processed

        print_bar()
        print("\nAnalyzing Commit: " + str(commit.hash) + " in " + repo_url + "\n")

        for modification in commit.modified_files:
            modified_files_content = modification.source_code
            if modified_files_content and is_source_code(modification.new_path):
                print_bar()
                print("\nAnalyzing " + str(modification.new_path) + "\n")
                guard = createGuard(modified_files_content)
                debt = debtDetect(modified_files_content, guard)
                debt["location"]=str(modification.new_path) 
                debt["repository"]=repo_url
                print(debt)
                debts[commit.hash] = debt
                # Save progress after analyzing each modified file in a commit
                with open(debts_file, 'w') as file:
                    print("Saving to Debts JSON...")
                    json.dump(debts, file, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a GitHub repository for technical debts.")
    parser.add_argument("repo_url", help="URL of the GitHub repository to analyze")
    parser.add_argument("--resume", action="store_true", help="Resume from the last saved state")
    args = parser.parse_args()

    main(args.repo_url, args.resume)


