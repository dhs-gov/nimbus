"""
Miscellaneous utilities
"""

import sys

def prompt_choices(choices, prompt='Please choose an option:',
                   input_prompt='Selection: ',
                   stream=sys.stderr):

    # loop until we get a valid selection
    while True:
        stream.write(prompt + '\n')
        for i, choice in enumerate(choices):
            stream.write('[{0}]: {1}\n'.format(i, choice))

        chosen = raw_input(input_prompt)

        try:
            index = int(chosen)
            if index >= 0:
                return choices[index]
        except (ValueError, IndexError):
            pass

