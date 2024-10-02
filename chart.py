import json
import os

from wth.utils.dataclass import deserialize

from pyecharts import options as opts
from pyecharts.charts import Pie

from preprocessor.impl.statistics import Counter

count = {}

for cur_dir, _, files in os.walk("./datasets/USTC-Statistics"):
    last_name = cur_dir.split("/")[-1]
    for file in files:
        data_dict = json.load(open(os.path.join(cur_dir, file), "r"))
        data = deserialize(data_dict, Counter)

        count[last_name] = data.pcap.pcap

c = (
    Pie()
    .add("", [list(z) for z in zip(count.keys(), count.values())])
    .set_global_opts(title_opts=opts.TitleOpts(title="Pie-基本示例"))
    .set_series_opts(label_opts=opts.LabelOpts(formatter="{b}: {c}"))
    .render("chart.html")
)
