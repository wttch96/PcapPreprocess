> pcap 原始文件处理, 我的 pacp 文件预处理大集合。
>
> 所有的实验的预处理都讲放到这个项目里。

# 整体框架

# 已实现的预处理类

利用下面的命令可以显示所有可以进行预处理的方法和可以预处理的数据集。

```bash
python main.py --show-methods
```

这是一个命令结果的例子:

```text
Active profile[local].
glads:
        vpn
capsule:
        USTC-Capsule-20-1000
```

`glads` 和 `capsule` 为预处理方法, `vpn` 和 `USTC-Capsule-20-1000`分别为 `glads` 和 `capsule` 对应可以处理的数据集。

> 数据集是在 [config.yml](./config.yml) 中定义的。处理方法需要参见具体的实现。


进行数据集预处理:

这是一个例子:

```bash
python main.py --method capsule --dataset UTSC-Capsule-20-1000
```

使用 capsule 方法 对数据集 UTSC-Capsule-20-1000 进行处理。

# 预处理方法

## 胶囊网络(capsule)

论文 Capsule Network Assisted IoT Traffic Classification Mechanism for Smart Cities 的数据预处理器实现。

论文地址: https://ieeexplore.ieee.org/abstract/document/8651277

预处理的[实现](./impl/capsule.py)