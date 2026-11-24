"""Deterministic URL character representations and a small offline CNN."""

import copy

import numpy as np
from sklearn.metrics import average_precision_score
import torch
from torch import nn
from torch.nn import functional as F

SEED = 143
LENGTH = 160
ALPHABET = "".join(chr(i) for i in range(32, 127))
CHARACTERS = {char: index for index, char in enumerate(ALPHABET, start=2)}
VOCABULARY = len(ALPHABET) + 2
KERNELS = (3, 5, 7)
BATCH = 256


def tokenize(text):
    result = np.zeros(LENGTH, dtype=np.int64)
    for i, char in enumerate(text[:LENGTH]):
        result[i] = CHARACTERS.get(char, 1)
    return result


def represent(row, kind):
    """Produce one model input while preserving its canonical join key."""
    if kind == "numeric":
        value = row["x"]
    elif kind == "ngram":
        value = row["normalizedUrl"]
    elif kind in ("cnn", "transformer"):
        tokens = tokenize(row["normalizedUrl"])
        value = tokens if kind == "cnn" else {"input_ids": tokens, "attention_mask": tokens != 0}
    else:
        raise ValueError("Unknown representation")
    return row["id"], row["partition"], value


class CharacterCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.embedding = nn.Embedding(VOCABULARY, 16, padding_idx=0)
        self.convolutions = nn.ModuleList(nn.Conv1d(16, 16, kernel) for kernel in KERNELS)
        self.dropout = nn.Dropout(0.2)
        self.head = nn.Linear(16 * len(KERNELS), 1)

    def forward(self, tokens):
        embedded = self.embedding(tokens).transpose(1, 2)
        lengths = (tokens != 0).sum(dim=1, keepdim=True)
        pooled = []
        for kernel, convolution in zip(KERNELS, self.convolutions, strict=True):
            activations = F.relu(convolution(embedded))
            valid = torch.arange(activations.shape[-1], device=tokens.device) + kernel <= lengths
            peaks = activations.masked_fill(~valid[:, None, :], 0).amax(dim=-1)
            pooled.append(peaks)
        return self.head(self.dropout(torch.cat(pooled, dim=1))).squeeze(-1)


def predict(model, inputs):
    model.eval()
    with torch.inference_mode():
        return np.concatenate([model(batch).sigmoid().numpy() for batch in torch.as_tensor(inputs).split(BATCH)])


def fit(train, labels, tuning, tuning_labels, epochs=8):
    torch.manual_seed(SEED)
    torch.use_deterministic_algorithms(True)
    model = CharacterCNN()
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.003)
    inputs = torch.as_tensor(train)
    targets = torch.as_tensor(labels, dtype=torch.float32)
    random = torch.Generator().manual_seed(SEED)
    best_score = -1
    best_epoch = 0
    best_state = None
    history = []
    for epoch in range(1, epochs + 1):
        model.train()
        for indices in torch.randperm(len(inputs), generator=random).split(BATCH):
            optimizer.zero_grad(set_to_none=True)
            loss = F.binary_cross_entropy_with_logits(model(inputs[indices]), targets[indices])
            loss.backward()
            optimizer.step()
        score = float(average_precision_score(tuning_labels, predict(model, tuning)))
        history.append(score)
        if score > best_score + 0.0001:
            best_score, best_epoch = score, epoch
            best_state = copy.deepcopy(model.state_dict())
        elif epoch - best_epoch >= 2:
            break
    model.load_state_dict(best_state)
    model.eval()
    return model, {"tuningAveragePrecisionByEpoch": history, "bestEpoch": best_epoch,
                   "parameters": sum(value.numel() for value in model.parameters()),
                   "vocabularySize": VOCABULARY, "sequenceLength": LENGTH, "truncation": "prefix",
                   "kernels": KERNELS, "batchSize": BATCH}
