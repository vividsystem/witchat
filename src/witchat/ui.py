from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Footer, Header


class RagdollApp(App):
    BINDINGS = [("s", "send_message", "Send message")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

    def action_send_message(self) -> None:
        print("message sent!")
