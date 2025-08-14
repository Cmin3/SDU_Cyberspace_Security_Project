# 基于Circom的Poseidon2哈希算法电路实现

## 一、项目概述

本项目使用Circom语言实现了Poseidon2哈希算法的零知识证明电路，采用Groth16证明系统生成证明。Poseidon2是一种专为零知识证明优化的哈希算法，具有计算效率高、证明生成快的特点。本实现严格遵循Poseidon2论文规范，提供了完整的电路实现和验证功能，适用于需要隐私保护的区块链和密码学应用场景。

## 二、算法原理详解

### 1. Poseidon2哈希算法核心结构

Poseidon2采用海绵结构，包含以下核心组件：

- **置换函数(Permutation)**：由多轮加密操作组成
- **S-Box层**：非线性变换层，使用x⁵操作
- **线性层**：MDS矩阵乘法
- **轮常数加法**：每轮添加的常量值

### 2. 具体参数配置

本实现采用(n,t,d)=(256,3,5)参数：

- 状态宽度(t)：3
- 全轮数(RF)：8轮（前后各4轮）
- 部分轮数(RP)：56轮
- S-Box指数(d)：5

### 3. 轮操作流程

1. **前半全轮**：4轮全状态S-Box变换
2. **部分轮**：56轮仅对部分状态进行S-Box变换
3. **后半全轮**：4轮全状态S-Box变换

### 4. 电路验证原理

- **公开输入**：哈希结果digest
- **私有输入**：原始消息preimage
- 电路验证preimage经过Poseidon2哈希后等于digest

## 三、文件说明

### poseidon2_reworked.circom

主电路文件包含：

1. **Poseidon2Core模板**：
   - 实现核心置换函数
   - 包含完整的轮常数和MDS矩阵
   - 实现S-Box和线性层变换

2. **Poseidon2HasherTop模板**：
   - 提供对外的哈希接口
   - 初始化状态为[0, preimage, 0]
   - 输出置换结果的第一个元素作为哈希值

3. **主组件声明**：
   - 定义公开输出digest
   - 定义私有输入preimage

## 四、构建与运行

### 1. 环境准备

安装依赖：

```bash
npm install -g circom
npm install -g snarkjs
```

### 2. 电路编译

```bash
circom poseidon2_reworked.circom --r1cs --wasm --sym
```

### 3. 可信设置

```bash
snarkjs powersoftau new bn128 12 pot12_0000.ptau
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau
snarkjs groth16 setup poseidon2_reworked.r1cs pot12_final.ptau poseidon2_0000.zkey
```

### 4. 生成证明

```bash
snarkjs groth16 prove poseidon2_0000.zkey witness.wtns proof.json public.json
```

### 5. 验证证明

```bash
snarkjs groth16 verify verification_key.json public.json proof.json
```

## 五、实现特点

1. **高效性**：
   - 优化部分轮实现，减少约束数量
   - 使用预计算轮常数提高性能

2. **正确性**：
   - 严格遵循Poseidon2论文规范
   - 包含完整的轮常数和MDS矩阵验证

3. **灵活性**：
   - 模块化设计便于参数调整
   - 可扩展支持不同状态宽度

4. **安全性**：
   - 使用标准密码学参数
   - 完善的轮常数设计

5. **兼容性**：
   - 输出格式兼容主流零知识证明系统
   - 可直接集成到现有zk-SNARK应用

