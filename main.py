from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from hash_checker import HashDatabase


PROJECT_DIRECTORY = Path(__file__).resolve().parent
LOGO = r"""
                 .:-=++++======++++=-:.
             .-=+=-:.              .:-=+=-.
           -++-.                        .-++-
        .+*-.                              .-*+.
      .+*-                                    -*+.
     =#-   .=-        ............        -=.   -#=
    **  ::#%=    ..  ..  .    .  ..  ..    =%#::  **
   #= :@-##+   .......  .. .:  .  .......   +##-@: =#
  #=.-@#-**- ..    .   .. #==@=..   .    .. -**-#@-.=#
 +* @-%#*+. ..    .    .. :.+#: .    .    .. .+*#%-@ *+
.% -@=++#- .. .. ..    .   :-   .    .. .. .. -#++=@- %.
*+ -@+*@= ..     .    .:.  ** ..:.    .     .. =@*+@- +*
@.+:*@#-: .      .     .  .::.  .     .      . :-#@*:+.@
@ *#.*:@: .     ..     :+:-%%-:+:     ..     . :@:*.#* @
@ .@*.@*  .     ..==+*#@@  **  @@#*+==..     .  *@.*@. @
@::=@%%:= .      +@@@@@@#  ##  #@@@@@@+      . =:%%@=::@
*==*:#+-@  .     #@@@@@@@: @@ :@@@@@@@#     .  @-+#:*==*
.% *@*:*@:... . .@@@@@@@@@:@@:@@@@@@@@@. . ...:@*:*@* %.
 +* +%%*@:#-..  :@@@@@@@@@@@@@@@@@@@@@@:  ..-#:@*%%+ *+
  #=.+=+#+=@: . +@@@@@@@@@@@@@@@@@@@@@@+ . :@=+#+=+.=#
   #=:##*+:%%:=.#@@@@@@@@@@@@@@@@@@@@@@#.=:%%:+*##:=#
    *+ :#%%*@#=%@@@@@@@@@@@@@@@@@@@@@@@@%=#@*%%#: +*
     =#: -+*+*+=%@@@@@@@@@@@@@@@@@@@@@@%=+*+*+- :#=
      .+*-:-*###*+++#@@@@@@@@@@@@@@#+++*###*-:-*+.
        .++-.:=+**#%@@@@@@@@@@@@@@@@%#**+=:.-++.
          .-++=--::.*@@@@@@@@@@@@@@*.::--=++-.
             .-===-:%@@@@@@@@@@@@@@%:-===-.
                 .:=+*#%@@@@@@@@%#*+=:.
"""
TITLE = r"""
              COLD HASH CHECKER
              Version 1.0
              File Integrity & Hash Analysis
"""
BANNER = LOGO + TITLE


def print_result(result: Dict[str, Any]) -> None:
    print("\n" + "=" * 60)

    if result.get("status") == "ERROR":
        print(f"File: {result.get('file_path', 'Unknown')}")
        print("Status: ERROR")
        print(f"Error: {result.get('error', 'Unknown error')}")
        print("=" * 60)
        return

    print(f"File: {result['file_name']}")
    print(f"Path: {result['file_path']}")
    print(f"Size: {result['file_size']} bytes")
    print("\nHashes:")

    for name, value in result["hashes"].items():
        print(f"{name.upper()}: {value}")

    print(f"\nStatus: {result['status'].upper()}")

    if result["match"] is not None:
        print(f"Database entry: {result['match']}")

    print("=" * 60)


def main() -> None:
    database_path = PROJECT_DIRECTORY / "database" / "known_hashes.json"
    try:
        checker = HashDatabase(database_path)
    except (OSError, ValueError) as error:
        print(f"Error loading hash database: {error}")
        return

    print(BANNER)

    while True:
        print("\n[1] Analyze File")
        print("[2] Scan Directory")
        print("[3] Show Database Information")
        print("[4] Add File to Known Hashes")
        print("[0] Exit")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            file_path = input("Enter file path: ").strip().strip('"')

            try:
                result = checker.analyse_file(file_path)
                print_result(result)

                if input("\nSave report? (y/n): ").strip().lower() == "y":
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    report_path = (
                        PROJECT_DIRECTORY / "reports" / f"file_{timestamp}.json"
                    )
                    checker.export_results([result], report_path)
                    print(f"Report saved: {report_path}")
            except (OSError, ValueError) as error:
                print(f"Error: {error}")

        elif choice == "2":
            directory = input("Enter directory path: ").strip().strip('"')

            try:
                results = checker.scan_directory(directory)
                matches = [
                    result for result in results if result["status"] == "known"
                ]
                errors = [
                    result for result in results if result["status"] == "ERROR"
                ]

                print(f"\nFiles processed: {len(results)}")
                print(f"Known hash matches: {len(matches)}")
                print(f"Errors: {len(errors)}")

                for match in matches:
                    print(f"[MATCH] {match['file_path']}")
                for error in errors:
                    print_result(error)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_path = (
                    PROJECT_DIRECTORY / "reports" / f"scan_{timestamp}.json"
                )
                checker.export_results(results, report_path)
                print(f"\nReport saved: {report_path}")
            except (OSError, ValueError) as error:
                print(f"Error: {error}")

        elif choice == "3":
            print("\nDatabase Information")
            print(f"Loaded entries: {len(checker.known_hashes)}")
            print(f"Location: {checker.database_path}")

        elif choice == "4":
            file_path = input("Enter file path: ").strip().strip('"')

            try:
                result = checker.analyse_file(file_path)
                label = input("Label for this hash: ").strip()
                checker.add_entry(
                    result["hashes"]["sha256"],
                    {"name": label or result["file_name"]},
                )
                print(f"Added SHA-256 {result['hashes']['sha256']}")
            except (OSError, ValueError) as error:
                print(f"Error: {error}")

        elif choice == "0":
            print("\nExiting Cold Hash Checker...")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting Cold Hash Checker...")
