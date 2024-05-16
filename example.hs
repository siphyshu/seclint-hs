import System.IO.Unsafe (unsafePerformIO)
import System.IO (openFile, hClose, IOMode(..))

main = do
    let x = unsafePerformIO (putStrLn "Hello, World!")
    putStrLn "This is a test"
    h <- openFile "test.txt" ReadMode
    -- forgot to close the file handle
    case x of
        _ -> putStrLn "Pattern match example"
