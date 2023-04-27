// Write a main function that just adds 2 numbers together
fn main() {
    let mut x = 5;
    let y = &mut x;
    *y = *y + 1;
    println!("y = {}", y);
    println!("{}", *y == 6);
    if x == 5 {
        println!("x is 5");
    } else {
        println!("x is not 5");
    }
}
