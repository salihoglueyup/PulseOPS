"""AI analysis panel: streams the local model's reading of the current telemetry; follow-up questions."""
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Input, Static

DIM = "#8b949e"


class AIModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Kapat")]

    DEFAULT_CSS = """
    AIModal { align: center middle; }
    #ai-dialog { width: 92%; height: 90%; border: round #30363d; background: #0d1117; padding: 0 1; }
    #ai-title { height: 1; color: #f0f6fc; text-style: bold; }
    #ai-scroll { height: 1fr; }
    #ai-answer { height: auto; }
    #ai-status { height: 1; color: #8b949e; }
    #ai-input { height: 3; }
    """

    def __init__(self, conversation, model: str, hostname: str, **kwargs):
        super().__init__(**kwargs)
        self.conversation = conversation
        self.model = model
        self.hostname = hostname
        self.transcript = Text()
        self.busy = False

    def compose(self) -> ComposeResult:
        with Vertical(id="ai-dialog"):
            yield Static(Text(f"🤖 AI ANALİZİ · {self.model} · {self.hostname}  (yerel, ESC ile kapat)"), id="ai-title")
            with VerticalScroll(id="ai-scroll"):
                yield Static(self.transcript, id="ai-answer")
            yield Static("", id="ai-status")
            yield Input(placeholder="Takip sorusu yazın ve Enter'a basın (ör. SSH saldırıları ne kadar ciddi?)",
                        id="ai-input")

    def on_mount(self) -> None:
        self.ask(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        question = event.value.strip()
        if question and not self.busy:
            event.input.value = ""
            self.ask(question)

    def ask(self, question) -> None:
        self.busy = True
        if question:
            self.transcript.append(f"\n\n❯ {question}\n\n", style="bold #58a6ff")
        self._set_status("Model düşünüyor... (yanıt geldikçe akar)")
        self._refresh()
        self._run(question)

    @work(thread=True, exclusive=True)
    def _run(self, question) -> None:
        from pulseops.ai import AIError

        try:
            self.conversation.ask(question, on_piece=lambda piece: self.app.call_from_thread(self._append, piece))
            self.app.call_from_thread(self._done, None)
        except AIError as e:
            self.app.call_from_thread(self._done, str(e))
        except Exception as e:  # never take the TUI down
            self.app.call_from_thread(self._done, f"Beklenmeyen hata: {e}")

    def _append(self, piece: str) -> None:
        # Plain Text: the model's output is never interpreted as Rich markup
        self.transcript.append(piece, style="#e6edf3")
        self._refresh()

    def _done(self, error) -> None:
        self.busy = False
        if error:
            self.transcript.append(f"\n❌ {error}\n", style="bold #f85149")
            self._set_status("Hata. Ayarlar: pulseops config ([ai]) · kontrol: pulseops ai status")
        else:
            self._set_status("ℹ️ Model çıktısıdır: komutları çalıştırmadan önce doğrulayın. Takip sorusu sorabilirsiniz.")
        self._refresh()

    def _set_status(self, text: str) -> None:
        self.query_one("#ai-status", Static).update(Text(text, style=DIM))

    def _refresh(self) -> None:
        self.query_one("#ai-answer", Static).update(self.transcript)
        self.query_one("#ai-scroll", VerticalScroll).scroll_end(animate=False)
