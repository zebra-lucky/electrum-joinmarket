# -*- coding: utf-8 -*-

import random


"""
The following defaults are maintained as accessed via functions for
flexibility.
TODO This should be moved from this module."""
MAX_DEFAULT_REL_FEE = 0.004
MIN_MAX_DEFAULT_ABS_FEE = 4000
MAX_MAX_DEFAULT_ABS_FEE = 40000


def get_default_max_relative_fee():
    return MAX_DEFAULT_REL_FEE


def get_default_max_absolute_fee():
    return random.randint(MIN_MAX_DEFAULT_ABS_FEE, MAX_MAX_DEFAULT_ABS_FEE)


def get_max_cj_fee_values(jmman, user_callback):
    """ Given a jmman object, retrieve the chosen maximum absolute
    and relative coinjoin fees chosen by the user, or prompt
    the user via the user_callback function, if not present in
    the config.

    user_callback:
    Arguments: relative value(default None), absolute value (default None)
    Returns: relative value (float), absolute value (int, satoshis)
    """
    jmconf = jmman.jmconf

    fee_values = [None, None]

    if jmconf.max_cj_fee_confirmed:
        for i, option in enumerate(('max_cj_fee_rel', 'max_cj_fee_abs')):
            fee_values[i] = getattr(jmconf, option, None)

    if any(x is None for x in fee_values):
        fee_values = user_callback(*fee_values)

    return tuple(map(lambda j: fee_values[j], range(len(fee_values))))
