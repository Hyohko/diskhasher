use {custom_error::custom_error, indicatif::style::TemplateError};

custom_error! {pub HasherError
    RegexError{why: String} = "Regular expression failed => {why}",
    FileError{path: String, why: String} = "File/Directory error => '{path}': {why}",
    HashError{why: String} = "Hash error => {why}",
    ThreadingError{why: String} = "Thread operation failed => {why}",
    ParseError{why: String} = "Parse error => {why}",
    IoError{why: String} = "IO Failure => {why}",
    StyleError{why: String} = "ProgressBar style error => {why}"
}

impl From<TemplateError> for HasherError {
    fn from(error: TemplateError) -> Self {
        HasherError::StyleError {
            why: format!("{error:?}"),
        }
    }
}

// todo https://stackoverflow.com/questions/53934888/how-to-include-the-file-path-in-an-io-error-in-rust
impl From<std::io::Error> for HasherError {
    fn from(error: std::io::Error) -> Self {
        HasherError::IoError {
            why: format!("{:?} => {error:?}", error.kind()),
        }
    }
}
