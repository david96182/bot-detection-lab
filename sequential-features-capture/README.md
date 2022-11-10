
python -m cProfile -o test.pstats main.py
gprof2dot -f pstats test.pstats | dot -Tpng -o output.png && gwenview output.png

python -m cProfile -o test.profile test.py
snakeviz test.profile

20k - 3:16  - 3:05 with mp