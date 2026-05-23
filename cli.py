import typer
from threat_classifier import classify

app = typer.Typer(help="threat-classifier — SOC triage inference pipeline")


@app.command()
def main(text: str = typer.Argument(..., help="Input text to classify")) -> None:
    result = classify(text)
    typer.echo(f"label:      {result.label}")
    typer.echo(f"confidence: {result.confidence:.2f}")
    typer.echo(f"escalate:   {result.escalate}")


if __name__ == "__main__":
    app()
