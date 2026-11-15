import ast
import torch

def predict(model, batch):
    model.eval()
    with torch.no_grad():
        return model(batch)

def parse_literal(text):
    return ast.literal_eval(text)
