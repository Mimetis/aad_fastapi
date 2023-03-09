from typing import Optional


class AuthError(Exception):
    code: str
    description: str

    def __init__(
        self,
        code: Optional[str] = None,
        description: Optional[str] = None,
        status_code=401,
        exception: Optional[Exception] = None,
    ):
        self.populate_code(code, exception)
        self.populate_description(description, exception)
        super().__init__(self.description)
        self.status_code = status_code

    def populate_code(self, code, exception):
        if code is None and exception is not None:
            if hasattr(exception, "error"):
                code = exception.error
            elif hasattr(exception, "code"):
                code = exception.code
        self.code = code

    def populate_description(self, description, exception):
        if description is None and exception is not None:
            if hasattr(exception, "message"):
                description = exception.message
            elif hasattr(exception, "description"):
                description = exception.description
            elif hasattr(exception, "args") and len(exception.args) >= 1:
                description = exception.args[0]
        self.description = description
