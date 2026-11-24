"""Train a compact character Transformer using the Phase 5C token IDs."""

import copy

import numpy as np
from sklearn.metrics import average_precision_score
import torch
from torch import nn
from torch.nn import functional as F

from shared import SEED, VOCABULARY, represent

LENGTH = 80
WIDTH = 24
HEADS = 4
DEPTH = 2
BATCH = 192


class URLTransformer(nn.Module):
    def __init__(self):
        super().__init__()
        self.characters = nn.Embedding(VOCABULARY, WIDTH, padding_idx=0)
        self.positions = nn.Embedding(LENGTH + 1, WIDTH)
        self.cls = nn.Parameter(torch.zeros(1, 1, WIDTH))
        layer = nn.TransformerEncoderLayer(WIDTH, HEADS, dim_feedforward=48, dropout=0.15,
                                           activation="gelu", batch_first=True)
        self.encoder = nn.TransformerEncoder(layer, DEPTH, enable_nested_tensor=False)
        self.head = nn.Sequential(nn.Dropout(0.15), nn.Linear(WIDTH, 1))

    def forward(self, tokens):
        valid = tokens != 0
        values = torch.cat([self.cls.expand(len(tokens), -1, -1), self.characters(tokens)], dim=1)
        positions = self.positions(torch.arange(values.shape[1], device=tokens.device))
        padding = F.pad(~valid, (1, 0), value=False)
        hidden = self.encoder(values + positions, src_key_padding_mask=padding)
        return self.head(hidden[:, 0]).squeeze(1)


def inputs(rows):
    return np.stack([represent(row, "transformer")[2]["input_ids"][:LENGTH] for row in rows])


def predict(model, values):
    model.eval()
    with torch.inference_mode():
        batches = torch.as_tensor(values).split(BATCH)
        return np.concatenate([model(batch).sigmoid().numpy() for batch in batches])


def fit(x, y, tuning_x, tuning_y, learning_rate, epochs):
    torch.manual_seed(SEED)
    torch.use_deterministic_algorithms(True)
    model = URLTransformer()
    # Break the symmetry of layers cloned by TransformerEncoder.
    for layer in model.encoder.layers:
        for value in layer.parameters():
            if value.ndim > 1:
                nn.init.xavier_uniform_(value)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    values = torch.as_tensor(x)
    targets = torch.as_tensor(y, dtype=torch.float32)
    prng = torch.Generator().manual_seed(SEED)
    best_epoch = 0
    best_score = -1.0
    best = None
    history = []
    for epoch in range(epochs):
        model.train()
        for batch in torch.randperm(len(values), generator=prng).split(BATCH):
            optimizer.zero_grad(set_to_none=True)
            loss = F.binary_cross_entropy_with_logits(model(values[batch]), targets[batch])
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
        score = float(average_precision_score(tuning_y, predict(model, tuning_x)))
        history.append(score)
        print(f"epoch {epoch + 1} tuning average precision {score:.6f}", flush=True)
        if score > best_score + 0.0001:
            best_score = score
            best_epoch = epoch + 1
            best = copy.deepcopy(model.state_dict())
        elif epoch + 1 - best_epoch >= 2:
            break
    model.load_state_dict(best)
    return model.eval(), {"bestEpoch": best_epoch, "tuningAveragePrecision": history,
                          "selectionScore": best_score, "learningRate": learning_rate}


def restore(path):
    model = URLTransformer()
    model.load_state_dict(torch.load(path, map_location="cpu", weights_only=True))
    return model.eval()
