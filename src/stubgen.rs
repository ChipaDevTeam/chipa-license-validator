use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "py")]
    start_py_gen()?;
    Ok(())
}

#[cfg(feature = "py")]
fn start_py_gen() -> Result<(), Box<dyn Error>> {
    let stub = chipa_license_validator::py::stub_info()?;

    stub.generate()?;
    Ok(())
}
