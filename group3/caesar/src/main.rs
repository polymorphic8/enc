use std::io::stdin;

fn main() {
    loop {
        let mut input = String::new();
        stdin().read_line(&mut input).expect("Failed to read input");

        let output: String = input
            .trim()
            .chars()
            .map(|c| match c {
                'a'..='z' => (((c as u8 - b'a' + 3) % 26) + b'a') as char,
                'A'..='Z' => (((c as u8 - b'A' + 3) % 26) + b'A') as char,
                ' ' => ' ',
                _ => '�',
            })
            .collect();

        println!("{}", output);
    }
}
