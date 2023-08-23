from .cli import run
import cProfile

cProfile.runctx("run()", globals(), locals(), "profile2.pstat")
