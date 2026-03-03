from __future__ import annotations


class Error(Exception):
    pass


<<<<<<< HEAD
=======
class LexerError(Error):
    pass


>>>>>>> Rewrite lexer and parser
class ParserError(Error):
    pass


class ResolveError(Error):
    pass


class NullPointerDereference(Error):
    pass


class ArraySizeError(Error):
    pass


class ExpressionParserError(Error):
    pass
<<<<<<< HEAD


class ExpressionTokenizerError(Error):
    pass
=======
>>>>>>> Rewrite lexer and parser
