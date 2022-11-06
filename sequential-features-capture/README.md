
python -m cProfile -o test.pstats test.py
gprof2dot -f pstats test.pstats | dot -Tpng -o output.png && eog output.png

python -m cProfile -o test.profile test.py
snakeviz test.profile