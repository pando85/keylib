use keylib_sys::*;

fn main() {
    println!("keylib-sys basic example");

    // Initialize the authenticator using the safe API with empty callbacks
    let callbacks = Callbacks::default();

    let _auth = match Authenticator::new(callbacks) {
        Ok(auth) => auth,
        Err(e) => {
            eprintln!("Failed to initialize authenticator: {:?}", e);
            return;
        }
    };

    println!("Authenticator initialized successfully!");

    // The authenticator will be automatically cleaned up when it goes out of scope
    println!("Example completed successfully!");
}
