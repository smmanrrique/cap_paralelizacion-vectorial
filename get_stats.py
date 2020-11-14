import pandas as pd

TIME_ESC = 473.4

LEN = 1024

FLOP_IT = 2

def get_flops(time):
	return ((FLOP_IT * LEN) / time)

def get_gflops(flops):
	return flops / 10 ** 9

def get_time_in_seconds(time):
	return time / 10 ** 9

df = pd.read_csv("./results.csv", sep=",")

df["speedup"] = df["time(ns)"].apply(lambda x: TIME_ESC / x)
df["time(s)"] = df["time(ns)"].apply(get_time_in_seconds)
df["flops"] = df["time(s)"].apply(get_flops)
df["gflops"] = df["flops"].apply(get_gflops)

print(df)