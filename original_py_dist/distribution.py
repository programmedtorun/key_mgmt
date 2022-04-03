"""

  This distribution algorithm was written by Nate Rapport
  and is a a prototype of the minting algorithm to be 
  implemented for Kaon 

"""

import enum
from random import seed, choice, shuffle
from string import ascii_letters, digits
from hashlib import sha3_256
from math import log
import numpy as np
import matplotlib.pyplot as plt
from tabulate import tabulate
from time import time
from datetime import datetime

def max_difficulty(m, w, n, k):
    """
    w =: word size (eg hex, octet, binary), m =: match length
    Returns brute force difficulty in bits
    """
    non_hashed = int(n*m*log(w, 2))
    hashed = int(-2*k*(w**m)*log(1 - w**-m, 2))
    return f"{non_hashed} + {hashed} = {non_hashed + hashed}"

def print_max_difficulty(h=64, M=2**64/(10**6), w=16, n=3, k=3):
    print(f"\nMonetary supply: {M:0.2e} Kaon")
    print(f"Number n of m-digits matches to check: {n}")
    print(f"Number of iterations (k): {k}")
    print(f"Word size: {w} bits\n")
    header = [
        "Match length",
        "# Stashes possible",
        "Reward per stash",
        "Difficulty (bits)",
        "Max memory usage"]
    table = []
    for m in range(1, 12):
        N = w**m
        table.append([
            f"{m}",
            f"{N:e}",
            f"{round(M/N, 3)}",
            f"{max_difficulty(m, w, n, k)}",
            f"{convert_unit(4*h*w**m)}"]
        )

    print(tabulate(table, headers=header))

class SIZE_UNIT(enum.Enum):
   BYTES = 8
   KB = BYTES*10**3
   MB = BYTES*10**6
   GB = BYTES*10**9
   TB = BYTES*10**12
   PB = BYTES*10**15
   EB = BYTES*10**18
   SIZES = [BYTES, KB, MB, GB, TB, PB, EB]

def convert_unit(size_in_bits):
    """ Convert bits to a (somewhat) human-readable form """
    size_units = [
        SIZE_UNIT.BYTES,
        SIZE_UNIT.KB,
        SIZE_UNIT.MB,
        SIZE_UNIT.GB,
        SIZE_UNIT.TB,
        SIZE_UNIT.PB,
        SIZE_UNIT.EB]

    scale = log(size_in_bits, 10)
    exp_list = list(range(1, 18, 3))
    if scale > exp_list[-1]:
        return f"{round(size_in_bits/SIZE_UNIT.EB.value, 2)} {SIZE_UNIT.EB.name}"

    size = list(filter(lambda x: scale-x<0, exp_list))[0]
    idx = exp_list.index(size)
    size_val = SIZE_UNIT.SIZES.value[idx]
    size_name = size_units[idx].name
    if size_in_bits/size_val < 1:
        size_val = SIZE_UNIT.SIZES.value[idx-1]
        size_name = size_units[idx-1].name

    return f"{round(size_in_bits/size_val, 3)} {size_name}"

def plot_results(m, n, k, h):
    table = open('./results/mining.csv', 'r').read().splitlines()[1:]
    checks = []
    ts_diffs = []
    i = 0
    for row in table:
        stash_number, ts, n_proposed, n_checks, stash = row.split(',')
        if i > 0:
            ts_diffs.append(float(ts) - float(ts_prev))

        i += 1
        ts_prev = ts
        checks.append(int(n_proposed) + int(n_checks))
        if int(n_proposed) > int(n_checks):
            print(stash_number, n_proposed, n_checks)

    fig, ax = plt.subplots()
    # y = [0] + ts_diffs
    y = list(map(lambda x: 0 if x==0 else log(x, 10), checks))

    plt.title(f"Mining (m={m}, n={n}, k={k}, h={h})")
    plt.xlabel("# Stashes")
    plt.ylabel("Work (log10)")

    ylim = int(log(max(checks), 10)) + 1
    plt.ylim([0, ylim])
    plt.yticks(list(range(0, ylim, 1)))

    plt.scatter(list(range(1, len(checks) + 1)), y, marker=".", alpha=1, c="black")
    plt.show()

def split_digits(s, m):
    """
    Split a hex digest into non-overlapping substrings of length m

    Example:
        >>> split_digits('7ff563eb4630', 3)
        ['7ff', '563', 'eb4', '630']
    """
    return [s[m*i:m*i+m] for i in range(len(s)//m)]

def check_collision(candidate, address, m, n):
    """ Check for n m-digit collisions """
    c = list(map(lambda s: split_digits(s, m)[:n], [candidate, address]))
    for x, y in zip(*c):
        if x == y:
            return True

    return False

def check_iterated_collision(candidate, stash, m, n, k, h):
    """ Return True if a collision is found, else False """

    def check(candidate, stash, m, n, k, h):
        for j in range(k):
            stash = stash_to_check(stash, candidate, h)
            if check_collision(candidate, stash, m, 1):
                return True

        return False

    # collision can occur in either direction
    if check(candidate, stash, m, n, k, h) \
        or check(stash, candidate, m, n, k, h):
        return True

    return False

def stash_to_check(stash, candidate, h):
    """ Return hashed + salted stash """
    return sha3_256(str.encode(stash + candidate)).hexdigest()[:h]

def generate_candidate(h):
    """ Generate a random stash candidate
        h =: hash length
    """
    s = ''.join([choice(ascii_letters + digits) for _ in range(20)])
    original = sha3_256(str.encode(s)).hexdigest()[:h]
    candidate = sha3_256(str.encode(original)).hexdigest()[:h]
    return original, candidate

def is_viable(candidate, existing_stashes, m, n, k, h):
    """ Check whether a candidate collides with any existing stashes
        Return True if no collisions found, else False
        Also, return number of checks performed
    """
    address, hashed_address = "", ""
    i = 0
    for i, wallet in enumerate(existing_stashes):
        stash = existing_stashes[i]
        if check_collision(candidate, stash, m, n) \
            or check_iterated_collision(candidate, stash, m, n, k, h):
            return False, i

    return True, i

def mine(m=9, n=4, k=70, h=64, min_to_mine=0.5):
    """ h := hash_length, m =: match length """

    header = ["Stashes found", "Timestamp", "# Proposed", "# Checks", "Stash"]
    print(tabulate([], headers=header).split('\n')[0])
    with open('./results/mining.csv', 'w') as f:
        f.write(','.join(header) + '\n')

    with open('./results/haystack.txt', 'w') as g:
        g.write("Stash\n")

    existing_stashes, all_checks, table = [], [], []
    wallet_set, prefix_set = set(), {}
    for i in range(n):
        prefix_set[i] = set()

    checks, attempts = 0, 1

    start = time()
    original, candidate = generate_candidate(h)
    while (time() - start)/60 < min_to_mine and len(existing_stashes) < 16**m:
        viable, new_checks = is_viable(candidate, existing_stashes, m, n, k, h)
        checks += new_checks

        if viable and candidate not in wallet_set:
            with open('./results/haystack.txt', 'a') as g:
                g.write(original + '\n')

            existing_stashes.append(candidate)
            all_checks.append(checks)

            wallet_set.add(candidate)
            for i in range(n):
                prefix_set[i].add(candidate[i*m:i*m + m])

            t = time()
            ts = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f")
            table.append(list(map(str, [len(wallet_set), t, attempts, checks, original])))

            print('\t'.join(map(str, [len(wallet_set), ts, attempts, checks, original[:4]])))

            checks, attempts = 0, 0

        original, candidate = generate_candidate(h)
        attempts += 1
        while prefix_match(candidate, prefix_set, m, n):
            original, candidate = generate_candidate(h)
            attempts += 1

    with open('./results/mining.csv', 'a') as f:
        for row in table:
            f.write(','.join(row) + '\n')

    print(f"Elapsed time: {time() - start} seconds\n")
    plot_results(m, n, k, h)

def prefix_match(candidate, prefix_set, m, n):
    for i in range(n):
        if candidate[i*m:i*m + m] in prefix_set[i]:
            return True

    return False

def validate_haystack(m, n, k, h):
    haystack = open('results/haystack.txt', 'r').read().splitlines()[1:]

    stashes = []
    for stash in haystack:
        stashes.append(sha3_256(str.encode(stash)).hexdigest()[:h])

    shuffle(stashes) # to show that order doesn't matter
    for i, candidate in enumerate(stashes):
        viable, checks = is_viable(candidate, stashes[:i] + stashes[i+1:], m, n, k, h)
        if not viable:
            return False

    print("Haystack is valid")
    return True

if __name__=='__main__':
    """
    for j in range(1, 4):
        for i in range(0, 80, 10):
            print_max_difficulty(n=j, k=i)

    """
    # prototype testing
    # m, n, k, h = 2, 2, 5, 64
    # print_max_difficulty(n=2, k=15)
    # mine(m, n, k, h, min_to_mine=1)
    # validate_haystack(m, n, k, h)
    # plot_results(m, n, k, h)
