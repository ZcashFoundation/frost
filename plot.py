"""

Generate the graphs for the FROST performance blog post.

Install cargo-criterion:

cargo install cargo-criterion

Run the benchmarks with:

(check out old code)

cargo criterion --message-format=json 'FROST' | tee > benchmark-verify-all-shares.txt

(check out new code)

cargo criterion --message-format=json 'FROST' | tee > benchmark-verify-aggregate.txt

And then run:

python3 plot.py

It will generate the figures (names are partially hardcoded in each functions)
and will insert/update the tables inside `performance.md`
"""

import matplotlib.pyplot as plt
import numpy as np
import json


def load_data(filename):
    ciphersuite_lst = []
    fn_lst = []
    size_lst = []
    data = {}
    with open(filename, 'r') as f:
        for line in f:
            line_data = json.loads(line)
            if line_data['reason'] == 'benchmark-complete':
                ciphersuite, fn, size = line_data['id'].split('/')
                ciphersuite = ciphersuite.replace('FROST Signing ', '')
                size = int(size)
                unit = line_data['typical']['unit']
                time = line_data['typical']['estimate']
                assert unit == 'ns'
                if unit == 'ns':
                    time = time / 1e6
                if ciphersuite not in ciphersuite_lst:
                    ciphersuite_lst.append(ciphersuite)
                if fn not in fn_lst:
                    fn_lst.append(fn)
                if size in (2, 7, 67, 667):
                    size = {2: 3, 7: 10, 67: 100, 667: 1000}[size]
                if size not in size_lst:
                    size_lst.append(size)
                data.setdefault(ciphersuite, {}).setdefault(fn, {})[size] = time
    return ciphersuite_lst, fn_lst, size_lst, data


def plot(title, filename, get_group_value, group_lst, series_lst, fmt, figsize):
    x = np.arange(len(group_lst))  # the label locations
    total_width = 0.8
    bar_width = total_width / len(series_lst)  # the width of the bars

    fig, ax = plt.subplots(figsize=figsize)

    offsets = [-total_width / 2 + bar_width / 2 + (bar_width * i) for i in range(len(series_lst))]
    rect_lst = []
    for series_idx, series in enumerate(series_lst):
        values = [get_group_value(series_idx, series, group_idx, group) for group_idx, group in enumerate(group_lst)]
        rect = ax.bar(x + offsets[series_idx], values, bar_width, label=series)
        rect_lst.append(rect)

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Time (ms)')
    ax.set_title(title)
    ax.set_xticks(x, group_lst)
    ax.legend()

    for rect in rect_lst:
        ax.bar_label(rect, padding=3, fmt=fmt)

    fig.tight_layout()

    plt.savefig(filename)
    plt.close()


def times_by_size_and_function(data, ciphersuite, fn_lst, size_lst, fmt, suffix):
    group_lst = [str(int((size * 2 + 2) / 3)) + "-of-" + str(size) for size in size_lst]
    series_lst = fn_lst
    title = f'Times by number of signers and functions; {ciphersuite} ciphersuite'
    filename = f'times-by-size-and-function-{ciphersuite}-{suffix}.png'

    def get_group_value(series_idx, series, group_idx, group):
        return data[ciphersuite][series][size_lst[group_idx]]

    plot(title, filename, get_group_value, group_lst, series_lst, fmt, (8, 6))


def times_by_ciphersuite_and_function(data, ciphersuite_lst, fn_lst, size, fmt):
    ciphersuite_lst = ciphersuite_lst.copy()
    ciphersuite_lst.sort(key=lambda cs: data[cs]['Aggregate'][size])
    group_lst = fn_lst
    series_lst = ciphersuite_lst
    min_signers = int((size * 2 + 2) / 3)
    title = f'Times by ciphersuite and function; {min_signers}-of-{size}'
    filename = f'times-by-ciphersuite-and-function-{size}.png'

    def get_group_value(series_idx, series, group_idx, group):
        return data[series][group][size]

    plot(title, filename, get_group_value, group_lst, series_lst, fmt, (12, 6))


def verify_aggregated_vs_all_shares(data_aggregated, data_all_shares, ciphersuite_lst, size, fmt):
    ciphersuite_lst = ciphersuite_lst.copy()
    ciphersuite_lst.sort(key=lambda cs: data_aggregated[cs]['Aggregate'][size])
    group_lst = ciphersuite_lst
    series_lst = ['Verify all shares', 'Verify aggregated']
    min_signers = int((size * 2 + 2) / 3)
    title = f'Time comparison for Aggregate function; {min_signers}-of-{size}'
    filename = f'verify-aggregated-vs-all-shares-{size}.png'

    def get_group_value(series_idx, series, group_idx, group):
        data = [data_all_shares, data_aggregated][series_idx]
        return data[group]['Aggregate'][size]

    plot(title, filename, get_group_value, group_lst, series_lst, fmt, (8, 6))


def generate_table(f, data, ciphersuite_lst, fn_lst, size_lst):
    for ciphersuite in ciphersuite_lst:
        print(f'### {ciphersuite}\n', file=f)
        print('|' + '|'.join([''] + fn_lst) + '|', file=f)
        print('|' + '|'.join([':---'] + ['---:'] * len(fn_lst)) + '|', file=f)
        for size in size_lst:
            min_signers = int((size * 2 + 2) / 3)
            print('|' + '|'.join([f'{min_signers}-of-{size}'] + ['{:.2f}'.format(data[ciphersuite][fn][size]) for fn in fn_lst]) + '|', file=f)
        print('', file=f)
    print('', file=f)


if __name__ == '__main__':
    ciphersuite_lst, fn_lst, size_lst, data_aggregated = load_data('benchmark-verify-aggregate.txt')
    _, _, _, data_all_shares = load_data('benchmark-verify-all-shares.txt')

    import io
    import re
    with io.StringIO() as f:
        generate_table(f, data_aggregated, ciphersuite_lst, fn_lst, size_lst)
        f.seek(0)
        table = f.read()
    with open('performance.md') as f:
        md = f.read()
        md = re.sub('<!-- Benchmarks -->[^<]*<!-- Benchmarks -->', '<!-- Benchmarks -->\n' + table + '<!-- Benchmarks -->', md, count=1, flags=re.DOTALL)
    with open('performance.md', 'w') as f:
        f.write(md)

    size_lst = [10, 100, 1000]
    times_by_size_and_function(data_all_shares, 'ristretto255', fn_lst, size_lst, '%.2f', 'all-shares')
    times_by_size_and_function(data_aggregated, 'ristretto255', fn_lst, size_lst, '%.2f', 'aggregated')

    times_by_ciphersuite_and_function(data_aggregated, ciphersuite_lst, fn_lst, 10, '%.2f')
    times_by_ciphersuite_and_function(data_aggregated, ciphersuite_lst, fn_lst, 100, '%.1f')
    times_by_ciphersuite_and_function(data_aggregated, ciphersuite_lst, fn_lst, 1000, '%.0f')

    verify_aggregated_vs_all_shares(data_aggregated, data_all_shares, ciphersuite_lst, 10, '%.2f')
    verify_aggregated_vs_all_shares(data_aggregated, data_all_shares, ciphersuite_lst, 100, '%.1f')
    verify_aggregated_vs_all_shares(data_aggregated, data_all_shares, ciphersuite_lst, 1000, '%.0f')
