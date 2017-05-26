"""
Miscellaneous utilities
"""

import errno
import os
import sys

def prompt_choices(choices, prompt='Please choose an option:',
                   input_prompt='Selection: ',
                   stream=sys.stderr):
    """
    Prompt the user to choose between an enumerable of choices.

    :param choices: The set of options to choose between.
    :type choices: list
    """

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

def merged_dicts(lhs, rhs):
    """
    Recursively merge values from rhs overriding lhs.

    All dicts will be copied, but other objects will be passed by reference.
    """
    out = {}
    for key, lhs_val in lhs.iteritems():
        if key in rhs:
            rhs_val = rhs[key]
            if isinstance(lhs_val, dict) and isinstance(rhs_val, dict):
                # recurse
                out[key] = merged_dicts(lhs_val, rhs_val)
            else:
                # take rhs
                out[key] = rhs[key]
        else:
            # no rhs
            out[key] = lhs[key]

    # copy over remaining keys from rhs not in lhs
    for key, rhs_val in rhs.iteritems():
        if key in lhs:
            continue
        out[key] = rhs_val

    return out

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def is_interactive_default():
    """
    Return whether to assume interactivity by default.

    If the environment varible NIMBUS_BATCH is set and truthy, return False.

    Else, if STDIN and STDOUT are both connected to TTYs, return True.

    Otherwise, return False.
    """
    if os.environ.get('NIMBUS_BATCH'):
        return False
    return sys.stdin.isatty() and sys.stderr.isatty()
