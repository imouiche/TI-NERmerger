import argparse
import json
import re
import pandas as pd
from urllib.parse import urlparse


def nextLine(lines, i):
    next_line = lines[i + 1]
    while len(next_line.split(' ', 1)) != 2:
        i += 1
        next_line = lines[i + 1]
    return next_line


def createTables():
    soft_url = 'http://attack.mitre.org/software/'
    grp_url = 'http://attack.mitre.org/groups/'
    names = ['mitre_attack_software.csv', 'mitre_attack_group.csv']
    urls = [soft_url, grp_url]
    for i, url in enumerate(urls):
        tables = pd.read_html(url)
        if tables:
            table1 = tables[0]
            table1.to_csv(names[i], index=False)
            print(f"{names[i]} table created successfully.")
        else:
            print("No tables found on the page.")


def convert_to_bio(annotated_text):
    lines = annotated_text.strip().split('\n')
    bio_lines = []
    k = 0
    for i, line in enumerate(lines):
        parts = line.split(" ", 1)
        if len(parts) == 2:
            word, label = parts
            label = label.strip()

            bio, entity = label[0], label[2:]
            if bio == 'E':
                bio_lines.append(f"{word} I-{entity}")
            elif bio == 'S':
                bio_lines.append(f"{word} B-{entity}")
            else:
                bio_lines.append(f"{word} {label}")
        else:
            bio_lines.append(line)  # For lines with no entity label
            k += 1

    print(k)
    return '\n'.join(bio_lines)


def convert_to_bioes(annotated_text):
    lines = annotated_text.strip().split('\n')
    bioes_lines = []

    for i, line in enumerate(lines):
        parts = line.split(" ", 1)
        if len(parts) == 2:
            word, label = parts
            bio, entity = label[0], label[2:]
            if bio == 'O':
                bioes_lines.append(f"{word} O")
            elif bio == 'B':
                next_line = nextLine(lines, i)
                next_word, next_label = next_line.split(' ', 1)
                next_bio, next_entity = next_label[0], next_label[2:]
                if next_bio == 'I':
                    bioes_lines.append(f"{word} B-{entity}")
                else:
                    bioes_lines.append(f"{word} S-{entity}")
            elif bio == 'I':
                next_line = nextLine(lines, i)
                next_word, next_label = next_line.split(' ', 1)
                next_bio, next_entity = next_label[0], next_label[2:]
                if next_bio == 'I':
                    bioes_lines.append(f"{word} I-{entity}")
                else:
                    bioes_lines.append(f"{word} E-{entity}")
        else:
            bioes_lines.append(line)  # For lines with no entity label

    return '\n'.join(bioes_lines)


def detect_format(annotated_text):
    lines = annotated_text.strip().split('\n')

    for line in lines:
        parts = line.split(" ", 1)
        if len(parts) == 2:
            _, label = parts
            bio = label[0]

            if bio == 'E' or bio == 'S':
                return 'BIOES'

    return 'BIO'


def perform_1to1_mapping(dataset_content, source_labels, target_labels):
    lines = dataset_content.strip().split('\n')
    updated_lines = []

    for line in lines:
        parts = line.split(" ", 1)
        if len(parts) == 2:
            word, label = parts
            bio, entity = label[0], label[2:]

            # if entity in source_labels:
            if source_labels and entity in source_labels:  # do not attempt to index NA
                updated_lines.append(f"{word} {bio}-{target_labels[source_labels.index(entity)]}")
            else:
                updated_lines.append(line)
        else:
            updated_lines.append(line)  # For lines with no entity label

    return '\n'.join(updated_lines)


def prompt_user_for_labels(dataset_number):
    # print(f"Enter the labels for Dataset {dataset_number}:")
    labels = input(f"Dataset {dataset_number} eg. APT,LOC,TIME, or NA for not applicable: ").strip()
    if labels.lower() == 'na':
        return None
    else:
        return [label.strip() for label in labels.split(',')]


def prompt_user_for_labels_manyTo1(dataset_number):
    # print(f"Dataset {dataset_number} labels for Many-to-1 mappings")
    labels = input(f"Dataset {dataset_number}: ").strip()
    if labels.lower() == 'na':
        return None
    else:
        return [label_set.strip() for label_set in labels.split(';')]


def perform_many_to_1_mapping(dataset_content, many_labels_sets, target_labels):
    lines = dataset_content.strip().split('\n')
    updated_lines = []

    for line in lines:
        parts = line.split(" ", 1)
        if len(parts) == 2:
            word, label = parts
            bio, entity = label[0], label[2:]

            # Initialize a flag to check if the entity was found in any label set
            entity_found = False

            for many_labels_set in many_labels_sets:
                many_labels = many_labels_set.split(',')
                if entity in many_labels:
                    updated_lines.append(f"{word} {bio}-{target_labels[many_labels_sets.index(many_labels_set)]}")
                    entity_found = True
                    break  # Entity found, no need to check other label sets

            # If the entity was not found in any label set, append the original line
            if not entity_found:
                updated_lines.append(line)
        else:
            updated_lines.append(line)  # For lines with no entity label

    return '\n'.join(updated_lines)


def oneTo1Mappings(args):
    print(" ===================1-to-1 Mapping for Entity Labels=======================\n")

    apply_to_dataset1 = prompt_user("Would you like to apply it on Dataset 1?")

    labels_dataset1 = None
    labels_target_dataset1 = None
    labels_dataset2 = None
    labels_target_dataset2 = None

    if apply_to_dataset1:
        print("Dataset1 labels for 1to1 mappings comma-separated")
        labels_dataset1 = prompt_user_for_labels(1)
        print("Targets labels for 1to1 mappings comma-separated")
        labels_target_dataset1 = prompt_user_for_labels(1)

    print("\n")
    apply_to_dataset2 = prompt_user("Would you like to apply it on Dataset 2?")
    if apply_to_dataset2:
        print("Dataset2 labels for 1to1 mappings comma-separated (eg Area,HackOrg)")
        labels_dataset2 = prompt_user_for_labels(2)
        print("Targets labels for 1to1 mappings comma-separated (eg Area,HackOrg)")
        labels_target_dataset2 = prompt_user_for_labels(2)

    # Check if all label sets are "NA" and skip the function
    if all(label is None or (isinstance(label, list) and all(l.lower() == 'na' for l in label)) for
           label in
           [labels_dataset1, labels_target_dataset1, labels_dataset2, labels_target_dataset2]):
        print("No 1-to-1 mapping is required. Exiting.")
    else:
        # Check if the lengths of the label lists are the same
        if (labels_dataset1 and labels_target_dataset1 and len(labels_dataset1) != len(labels_target_dataset1)) or \
                (labels_dataset2 and labels_target_dataset2 and len(labels_dataset2) != len(labels_target_dataset2)):
            print("Error: The number of labels and target labels should be the same.")
        else:
            labels_info = {
                "labels_dataset1": labels_dataset1,
                "labels_target_dataset1": labels_target_dataset1,
                "labels_dataset2": labels_dataset2,
                "labels_target_dataset2": labels_target_dataset2
            }

            # Save the labels information to a JSON file
            labels_filename = 'labels.json'
            with open(labels_filename, 'w', encoding='utf-8') as labels_file:
                json.dump(labels_info, labels_file)

            # Use a different variable name (not args) for the Namespace object
            labels_args = argparse.Namespace(
                labels_file=labels_filename,
                input_file_1=args.input_file_1,  # The user will provide the path as a command-line argument
                input_file_2=args.input_file_2
            )

            # # Get the input file paths from the command-line arguments
            # parser = argparse.ArgumentParser(description='Convert BIO to BIOES format')
            # parser.add_argument('format_choice', choices=['BIO', 'BIOES'], help='Output format choice')
            # parser.add_argument('input_file_1', help='Path to the first input file')
            # parser.add_argument('input_file_2', help='Path to the second input file')
            # parser.add_argument('merged_output_file', help='Path to the merged output file')
            # args = parser.parse_args(namespace=labels_args)

            if apply_to_dataset1:
                with open(labels_args.input_file_1, 'r+', encoding='utf-8') as f1:
                    dataset1_content = f1.read()
                    # print("Original content of Dataset 1:")
                    # print(dataset1_content)

                    if labels_dataset1 and labels_target_dataset1:
                        updated_dataset1 = perform_1to1_mapping(dataset1_content, labels_dataset1,
                                                                labels_target_dataset1)
                        # print("Updated content of Dataset 1:")
                        # print(updated_dataset1)

                        with open(labels_args.input_file_1, 'w', encoding='utf-8') as f1_write:
                            f1_write.write(updated_dataset1)
                            print("Dataset 1 completed.\n")

            if apply_to_dataset2:
                with open(labels_args.input_file_2, 'r+', encoding='utf-8') as f2:
                    dataset2_content = f2.read()
                    if labels_dataset2 and labels_target_dataset2:
                        updated_dataset2 = perform_1to1_mapping(dataset2_content, labels_dataset2,
                                                                labels_target_dataset2)
                        with open(labels_args.input_file_2, 'w', encoding='utf-8') as f2_write:
                            f2_write.write(updated_dataset2)
                            print("Dataset 2 completed.\n")

            print("oneTo1Mappings completed.\n")


def manyTo1Mappings(args):
    print("===================Many-to-1 Mapping for Entity Labels===================")

    apply_to_dataset1 = prompt_user("Would you like to apply it on Dataset 1?")

    many_labels_dataset1 = None
    many_labels_target_dataset1 = None
    many_labels_dataset2 = None
    many_labels_target_dataset2 = None

    if apply_to_dataset1:
        print("Dataset1 labels for manyto1 mappings: eg. Idus,Org;Way,OffAct ")
        many_labels_dataset1 = prompt_user_for_labels_manyTo1(1)
        print("Target label sets for manyto1 mappings: eg. IDTY;ACT ")
        many_labels_target_dataset1 = prompt_user_for_labels_manyTo1(1)
    print("\n")
    apply_to_dataset2 = prompt_user("Would you like to apply it on Dataset 2?")
    if apply_to_dataset2:
        print("Dataset2 label sets for manyto1 mappings: eg. Idus,Org;Way,OffAct ")
        many_labels_dataset2 = prompt_user_for_labels_manyTo1(2)
        print("Target labels for manyto1 mappings: eg. IDTY;ACT ")
        many_labels_target_dataset2 = prompt_user_for_labels_manyTo1(2)

    # Check if all label sets are "NA" and skip the function
    if all(label_set is None or (isinstance(label_set, list) and all(l.lower() == 'na' for l in label_set)) for
           label_set in
           [many_labels_dataset1, many_labels_target_dataset1, many_labels_dataset2, many_labels_target_dataset2]):
        print("Skipping Many-to-1 mapping as all labels are 'NA'.")
    else:
        many_labels_info = {
            "many_labels_dataset1": many_labels_dataset1,
            "many_labels_target_dataset1": many_labels_target_dataset1,
            "many_labels_dataset2": many_labels_dataset2,
            "many_labels_target_dataset2": many_labels_target_dataset2
        }
        many_labels_filename = 'many_labels.json'
        with open(many_labels_filename, 'w', encoding='utf-8') as many_labels_file:
            json.dump(many_labels_info, many_labels_file)

        many_labels_args = argparse.Namespace(
            labels_file=many_labels_filename,
            input_file_1=args.input_file_1,
            input_file_2=args.input_file_2
        )

        content = many_labels_args.input_file_1
        # print("before reading", content)
        if apply_to_dataset1:
            with open(many_labels_args.input_file_1, 'r', encoding='utf-8') as f1:
                dataset1_content = f1.read()
                # print("Original content of Dataset 1:")
                # print(dataset1_content)

                if many_labels_dataset1 and many_labels_target_dataset1:
                    updated_dataset1 = perform_many_to_1_mapping(dataset1_content, many_labels_dataset1,
                                                                 many_labels_target_dataset1)
                    # print("Updated content of Dataset 1:")
                    # print(updated_dataset1)

                    with open(many_labels_args.input_file_1, 'w', encoding='utf-8') as f1_write:
                        f1_write.write(updated_dataset1)
                        print(" Dataset 1 completed. \n")

        if apply_to_dataset2:
            with open(many_labels_args.input_file_2, 'r', encoding='utf-8') as f2:
                dataset2_content = f2.read()
                if many_labels_dataset2 and many_labels_target_dataset2:
                    updated_dataset2 = perform_many_to_1_mapping(dataset2_content, many_labels_dataset2,
                                                                 many_labels_target_dataset2)
                    with open(many_labels_args.input_file_2, 'w', encoding='utf-8') as f2_write:
                        f2_write.write(updated_dataset2)
                        print(" Dataset 2 completed. \n ")

        print("manyTo1Mappings completed.\n")


# ============================ 1-to-many mappings =============================
def isFile(text):
    # Define a regular expression pattern to exclude domains
    exclude_domains_pattern = r'\.(com|net|org|gov|edu|fr)\b'
    cleaned_text = re.sub(r'[^\w\s.]+', '', text)

    # Compile the exclusion pattern
    # exclude_domains_regex = re.compile(exclude_domains_pattern, re.IGNORECASE)

    # Define a regular expression pattern to match file extensions file_extension_pattern = r'\.(
    file_extension_pattern = r'\.(jpg|gif|doc|pdf|exe|docx|sh|zip|tar|mp3|mp4|txt|dat|bash|dll|net|json|dcm|js|java' \
                             r'|py|php|html|css|mov|wav|xsl|eps|avi|ppt|xlsx|odt|mid|mpa|wma|aif|rar|gz|7z|arj|pkg' \
                             r'|rpm|wpl|csv|xml|sql|ps|jps|cer|pfx|jsp|xhtml|rss|pptx|png|jpeg|md|bak|)$'
    # Combine the exclusion pattern and file extension pattern
    combined_pattern = re.compile(fr'^.*{file_extension_pattern}(?!.*{exclude_domains_pattern})', re.IGNORECASE)

    if combined_pattern.match(cleaned_text):
        return 'FILE'
    else:
        return None


def isHash(text):
    # Define a regular expression pattern for various hash algorithms
    hash_pattern = r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})\b'
    cleaned_text = re.sub(r'[^\w\s.]+', '', text)
    # Example usage:
    matches = re.findall(hash_pattern, cleaned_text)

    if matches:
        return text
    else:
        return None


def sampleFile(entity, default_label):
    file_type = isFile(entity)
    if file_type:
        return file_type
    else:
        hash_value = isHash(entity)

        if hash_value:
            # Check hash length to determine the algorithm
            if len(hash_value) <= 32:
                return "MD5"
            elif len(hash_value) <= 40:
                return "SHA1"
            elif len(hash_value) <= 64:
                return "SHA2"
            elif len(hash_value) <= 128:
                return "SHA3"
            else:
                return "SHA3"
        else:
            return default_label  # default value


def transform_output(entity, software_type, entity_labels):
    transformed_output = []

    for word, label in zip(entity.split(), entity_labels):
        transformed_output.append(f"{word} {label}-{software_type}")

    return "\n".join(transformed_output)


def get_type_by_name(name, default_label, new_label):
    name = name.lower()
    file_path = "mitre_software.csv"
    df = pd.read_csv(file_path)

    row = df[df['NAME'].str.lower() == name]
    if not row.empty:
        if row['TYPE'].values[0] == 'TOOL':
            return new_label[0]
        else:
            return new_label[1]
    else:
        return default_label


def nextLine(lines, i):
    while i + 1 < len(lines):
        next_line = lines[i + 1]
        if len(next_line.split(' ', 1)) == 2:
            return next_line
        i += 1
    return None


def classify_file(text, dataset_number):
    lines = text.strip().split("\n")
    dataset_label = input(
        f"Dataset {dataset_number}, enter the file labels for entities to be classified (e.g., FILE/File): ").strip()
    default_label = input(
        f"Dataset {dataset_number}, enter the default label (e.g., FILE/MAL): ").strip()

    updated_dataset = []
    for i, line in enumerate(lines):
        # print("initial here", line)
        if line.split():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                word, label = parts
                if label[2:] == dataset_label and label[0] == 'S':
                    new_label = sampleFile(word, default_label)
                    updated_dataset.append(f"{word} S-{new_label}")
                elif label[2:] == dataset_label and label[0] == 'B':
                    next_line = nextLine(lines, i)
                    next_word, next_label = next_line.split(' ', 1)
                    if next_label[0] != 'I' and next_label[0] != 'E':
                        new_label = sampleFile(word, default_label)
                        updated_dataset.append(f"{word} B-{new_label}")

                else:
                    updated_dataset.append(line)
            else:
                updated_dataset.append(line)
        else:
            updated_dataset.append(line)

    return '\n'.join(updated_dataset)


def classify_exploit(text, dataset_number):
    print(f"For the dataset {dataset_number}")
    dataset_label = input("Enter the dataset exploit label to be classified eg. Exp: ")
    targetLabels = input("Enter the traget labels for the exploit name and ID, (eg. VULNAME,VULID) in the same order: ")

    target_labels = targetLabels.split(',')
    if all(l.lower() == 'na' for l in target_labels) or dataset_label == 'na':
        print("Skipping as all target labels are NA or dataset label is NA")
        return text

    lines = text.strip().split("\n")
    updated_dataset = []
    for i, line in enumerate(lines):
        # print("initial here", line)
        if line.split():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                word, label = parts
                if label[2:].upper() == dataset_label.upper():
                    if word.startswith("CVE") or word.startswith("(CVE"):
                        label = label.replace(label[2:], target_labels[1])
                    else:
                        label = label.replace(label[2:], target_labels[0])
                    updated_dataset.append(f"{word} {label}")

                else:
                    updated_dataset.append(f"{word} {label}")
            else:
                updated_dataset.append(line)

    return '\n'.join(updated_dataset)


def get_group_by_name(name, default_label, new_label):
    name = name.lower()
    file_path = "mitre_attack_group.csv"
    df = pd.read_csv(file_path)

    row = df[df['Name'].str.lower() == name]
    if not row.empty:
        return new_label
    else:
        return default_label


def software_label_update(text, dataset_number):
    # print("---------------ATT&CK Software Classification------------------\n")
    lines = text.strip().split("\n")
    dataset_labels = input(
        f"Dataset {dataset_number}, enter labels for software entities to be classified with Mitre platform (e.g., "
        f"TOOL) comma-separated if many or NA to skip: ").strip()
    # dataset_label = 'TOOL'
    # Check if all dataset labels are "NA" and skip the function
    if all(label.lower() == 'na' for label in dataset_labels.split(',')):
        print("Skipping the function as all labels are 'NA'.")
        return text

    new_label = input(
        f"Dataset {dataset_number}, enter the target labels for the Tool and Malware (eg., TOOL,MAL): ").strip()
    default_label = input(
        f"Dataset {dataset_number}, enter the default label name (eg., TOOL): ").strip()

    new_label = new_label.split(',')
    updated_dataset = []

    for dataset_label in dataset_labels.split(','):
        temp_dataset = []
        for i, line in enumerate(lines):
            # print("initial here", line)
            if line.split():
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    word, label = parts
                    entity = ''
                    if label[2:] == dataset_label:
                        if label[0] == 'S':
                            entity += word
                            software_type = get_type_by_name(entity, default_label, new_label)
                            # print(entity, software_type)
                            temp_dataset.append(f"{word} S-{software_type}")
                        entity_labels = []
                        if label[0] == 'B':
                            entity += word
                            entity_labels.append(f"B")
                            # print(entity, label[0])

                            next_line = nextLine(lines, i)
                            while next_line is not None:
                                next_word, next_label = next_line.split(' ', 1)
                                # print(next_word, next_label, next_label[0], next_label[2:])
                                if next_label[0] == 'I' and next_label[2:] == dataset_label:
                                    entity += ' ' + next_word
                                    entity_labels.append(f"I")
                                elif next_label[0] == 'E' and next_label[2:] == dataset_label:
                                    entity += ' ' + next_word
                                    entity_labels.append(f"E")
                                else:
                                    entity = entity
                                    break
                                i += 1
                                next_line = nextLine(lines, i)

                            software_type = get_type_by_name(entity, default_label, new_label)
                            # print(entity, software_type, entity_labels)
                            output = transform_output(entity, software_type, entity_labels)
                            # print("current output",output)
                            temp_dataset.append(output)
                    else:
                        # print("heya", line)
                        temp_dataset.append(line)
                else:
                    temp_dataset.append(line)
        lines = temp_dataset
        updated_dataset = lines
    return '\n'.join(updated_dataset)


def group_label_update(text, dataset_number):
    # print("--------------ATT&CK Group Classification-------------------- \n")
    lines = text.strip().split("\n")
    updated_dataset = []
    dataset_labels = input(f"Dataset {dataset_number}, enter the label for group entities to be classified with Mitre "
                           f"Repos groups, comma-separated if multiple (eg., HackOrg,MAL) or NA to skipp: ").strip()

    # Check if all dataset labels are "NA" and skip the function
    if all(label.lower() == 'na' for label in dataset_labels.split(',')):
        print("Skipping the function as all labels are 'NA'.")
        return text

    new_label = input(f"Dataset {dataset_number}, enter the target label name for the group (eg., APT): ").strip()
    default_label = input(f"Dataset {dataset_number}, enter the default label name (eg., APT): ").strip()
    # dataset_label = 'HackOrg,MAL'
    # default_label = 'Campaign'
    # new_label = 'APT'

    for dataset_label in dataset_labels.split(','):
        temp_dataset = []
        for i, line in enumerate(lines):
            # print("initial here", line)
            if line.split():
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    word, label = parts
                    entity = ''
                    if label[2:] == dataset_label:
                        if label[0] == 'S':
                            entity += word
                            group_type = get_group_by_name(entity, default_label, new_label)
                            # print(entity, software_type)
                            temp_dataset.append(f"{word} S-{group_type}")
                        entity_labels = []
                        if label[0] == 'B':
                            entity += word
                            entity_labels.append(f"B")
                            # print(entity, label[0])

                            next_line = nextLine(lines, i)
                            while next_line is not None:
                                next_word, next_label = next_line.split(' ', 1)
                                # print(next_word, next_label, next_label[0], next_label[2:])
                                if next_label[0] == 'I' and next_label[2:] == dataset_label:
                                    entity += ' ' + next_word
                                    entity_labels.append(f"I")
                                elif next_label[0] == 'E' and next_label[2:] == dataset_label:
                                    entity += ' ' + next_word
                                    entity_labels.append(f"E")
                                else:
                                    entity = entity
                                    break
                                i += 1
                                next_line = nextLine(lines, i)

                            group_type = get_group_by_name(entity, default_label, new_label)
                            # print(entity, software_type, entity_labels)
                            output = transform_output(entity, group_type, entity_labels)
                            # print("current output",output)
                            temp_dataset.append(output)
                    else:
                        # print("heya", line)
                        temp_dataset.append(line)
                else:
                    temp_dataset.append(line)
        lines = temp_dataset
        updated_dataset = lines
    return '\n'.join(updated_dataset)


def oneToManyMappings(args):
    print("===================== 1-to-many Module====================== \n")
    print("--------------- File Classification: File --> [FILE, SHA1, SHA2, SHA3]------------------\n")

    if prompt_user("Would you like to apply it on Dataset 1?"):
        with open(args.input_file_1, 'r', encoding='utf-8') as f1:
            annotated_text_1 = f1.read()
        annotated_text_1 = classify_file(annotated_text_1, 1)
        with open(args.input_file_1, 'w', encoding='utf-8') as f1:
            f1.write(annotated_text_1)
            print("File classification applied on dataset 1 \n")

    if prompt_user("Would you like to apply it on dataset 2?"):
        with open(args.input_file_2, 'r', encoding='utf-8') as f2:
            annotated_text_2 = f2.read()
        annotated_text_2 = classify_file(annotated_text_2, 2)
        with open(args.input_file_2, 'w', encoding='utf-8') as f2:
            f2.write(annotated_text_2)
            print("File classification applied on dataset 2")
    print('\n')

    print(
        "=============== Exploit Classification: Classify exploit into vulnerability name and vulnerability ID "
        "=======\n")
    if prompt_user("Would you like to apply it on dataset 1?"):
        with open(args.input_file_1, 'r', encoding='utf-8') as f1:
            annotated_text_1 = f1.read()
        annotated_text_1 = classify_exploit(annotated_text_1, 1)
        with open(args.input_file_1, 'w', encoding='utf-8') as f1:
            f1.write(annotated_text_1)
            print("Exploit classification applied on dataset 1")
        print('\n')
    if prompt_user("Would you like to apply it on dataset 2?"):
        with open(args.input_file_2, 'r', encoding='utf-8') as f2:
            annotated_text_2 = f2.read()
        annotated_text_2 = classify_exploit(annotated_text_2, 2)
        with open(args.input_file_2, 'w', encoding='utf-8') as f2:
            f2.write(annotated_text_2)
            print("Exploit classification applied on dataset 2")
    print('\n')

    print("---------------ATT&CK Software Classification: Tool/Malware --> [TOOL, MAL] ---------------\n")

    if prompt_user("Would you like to apply it on dataset 1?"):
        with open(args.input_file_1, 'r', encoding='utf-8') as f1:
            annotated_text_1 = f1.read()
        annotated_text_1 = software_label_update(annotated_text_1, 1)
        with open(args.input_file_1, 'w', encoding='utf-8') as f1:
            f1.write(annotated_text_1)
            print("Software update applied on dataset 1 \n")

    if prompt_user("Would you like to apply it on dataset 2?"):
        with open(args.input_file_2, 'r', encoding='utf-8') as f2:
            annotated_text_2 = f2.read()
        annotated_text_2 = software_label_update(annotated_text_2, 2)
        with open(args.input_file_2, 'w', encoding='utf-8') as f2:
            f2.write(annotated_text_2)
            print("Software update applied on dataset 2 \n")

    print('\n')
    print("---------------ATT&CK Group Classification: [TOOL, MAL] -> APT------------------\n")

    if prompt_user("Would you like to apply it on dataset 1?"):
        with open(args.input_file_1, 'r', encoding='utf-8') as f1:
            annotated_text_1 = f1.read()
        annotated_text_1 = group_label_update(annotated_text_1, 1)
        with open(args.input_file_1, 'w', encoding='utf-8') as f1:
            f1.write(annotated_text_1)
            print("Group update applied on dataset 1 \n")

    if prompt_user("Would you like to apply it on dataset 2?"):
        with open(args.input_file_2, 'r', encoding='utf-8') as f2:
            annotated_text_2 = f2.read()
        annotated_text_2 = group_label_update(annotated_text_2, 2)
        with open(args.input_file_2, 'w', encoding='utf-8') as f2:
            f2.write(annotated_text_2)
            print("Group update applied on dataset 2 \n")
        print("oneToManyMappings completed.\n")
    print('\n')


# ===================== Discovery of other IoCs=============================================
def discover_low_iocs(annotated_text, tagging, dataset_number):
    print(f"For the dataset {dataset_number}.")
    IP = input('Enter the target label for the IP address (eg. IP) or NA to skip: ').strip()
    URL = input('Enter the target label for the URLs (eg. URL) or NA to skip: ').strip()
    FILE = input('Enter the target label for any discovered file (eg. FILE) or NA to skip: ').strip()
    DOM = input('Enter the target label for the DNS (eg. DOM) or NA to skip: ').strip()
    EMAIL = input('Enter the target label for the email addresses (eg. EMAIL) or NA to skip: ').strip()
    PROT = input('Enter the target label for the protocols (eg. PROT) or NA to skip: ').strip()
    print('\n')
    target_labels = [IP, URL, FILE, DOM, EMAIL, PROT]
    # Check if all dataset labels are "NA" and skip the function
    if all(label.lower() == 'na' for label in target_labels):
        print("Skipping the function as all labels are 'NA'.")
        return annotated_text
    default_label = None
    patterns = [
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', IP),
        (r'\b(?:[-a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b', EMAIL)
    ]

    common_protocols = ['RDP', 'SSH', 'HTTP', 'HTTPS', 'TLS', 'FTP', 'SMTP', 'POP3', 'SFTP', 'IMAP', 'SSL', 'POP',
                        'UDP', 'TCP', 'IPV4', 'IPV6', 'OPENVPN', 'IPSEC', 'KEBEROS', 'SNMP', 'DTLS', 'SASE', 'TELNET']

    lines = annotated_text.strip().split('\n')
    replaced_lines = []

    if tagging.upper() == 'BIO':
        tag = 'B'
    elif tagging.upper() == 'BIOES':
        tag = 'S'

    for line in lines:
        parts = line.split(" ", 1)
        if len(parts) == 2:
            word, label = parts
            # word = re.sub(r'[^\w\s.]+', '', word)
            if label == 'O' and word != '.':

                for pattern, new_label in patterns:
                    if re.search(pattern, word):
                        label = f'{tag}-{new_label}'
                        break
                else:
                    # If the loop completes without break, check for URL, domain, or protocol
                    parsed_url = urlparse(word)
                    new_label = sampleFile(word, default_label)
                    if new_label:
                        if new_label == 'FILE':
                            label = f'{tag}-{FILE}'
                        else:
                            label = f'{tag}-{new_label}'
                    elif parsed_url.netloc:  # If netloc exists, it's a URL
                        label = f'{tag}-{URL}'
                    elif '.' in word and not word.endswith('.'):  # If it contains a dot, it's a domain
                        label = f'{tag}-{DOM}'
                    elif word.upper() in common_protocols:  # Check for common protocols
                        label = f'{tag}-{PROT}'
                    else:
                        label = label

                replaced_lines.append(f"{word} {label}")
            else:
                replaced_lines.append(line)
        else:
            replaced_lines.append(line)

    return '\n'.join(replaced_lines)


def discoveryIOCs(args):
    print("This module discovers low-level IoCs (IP, URL, DOM, EMAIL), common protocols found in CTI reports (UDP, "
          "HTTPs, RDP, etc) and files (eg. .exe, .mp4, ect).\n")

    if prompt_user("Would you like to apply it on Dataset 1?"):
        with open(args.input_file_1, 'r', encoding='utf-8') as f1:
            annotated_text_1 = f1.read()
        annotated_text_1 = discover_low_iocs(annotated_text_1, args.format_choice, 1)
        with open(args.input_file_1, 'w', encoding='utf-8') as f1:
            f1.write(annotated_text_1)
            print("IoC discovery applied on dataset 1 \n")

    if prompt_user("Would you like to apply it on Dataset 2?"):
        with open(args.input_file_2, 'r', encoding='utf-8') as f2:
            annotated_text_2 = f2.read()
        annotated_text_2 = discover_low_iocs(annotated_text_2, args.format_choice, 2)
        with open(args.input_file_2, 'w', encoding='utf-8') as f2:
            f2.write(annotated_text_2)
            print("IoC discovery applied on dataset 2 \n")
        print('discoveryIOCs completed.\n')


# ===================================== Discovery of Encryption Algorithms=======================
def get_encryption_by_name(name, default_label, new_label):
    name = name.lower()
    file_path = "encryption_algorithms.csv"
    df = pd.read_csv(file_path)

    row = df[df['ENCR_Algorithms'].str.lower() == name]
    if not row.empty:
        return new_label
    else:
        return default_label


def discover_encr(text, tagging, dataset_number):
    lines = text.strip().split("\n")
    print(f"For Dataset {dataset_number}")
    new_label = input(
        "Enter the label for all discovered encryption entities in the dataset (eg. ENCR) or NA to skip: ").strip()

    # Check if all dataset labels are "NA" and skip the function
    if new_label.lower() == 'na' or len(new_label.split(',')) > 1:
        print("Skipping the function as label is 'NA' and/or len(new_label.split(',')) > 1.")
        return text

    default_label = 'O'

    # print(new_label)

    if tagging == 'BIO':
        tag = 'B'
    elif tagging == 'BIOES':
        tag = 'S'

    updated_dataset = []
    for i, line in enumerate(lines):
        if line.split():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                word, label = parts
                if label.startswith('O'):
                    new_label2 = get_encryption_by_name(word, default_label, new_label)
                    # print(new_label2)
                    if new_label2 != default_label:
                        updated_dataset.append(f"{word} {tag}-{new_label2}")
                    else:
                        updated_dataset.append(f"{word} {label}")

                else:
                    updated_dataset.append(line)
            else:
                updated_dataset.append(line)

    return '\n'.join(updated_dataset)


def discover_encry_algorithms(args):
    print("This module discovers common encryption algorithms (3DES, AES, SHA1, base64, RSA, etc ) found in CTI "
          "reports.\n")
    if prompt_user("Would you like to apply it on Dataset 1?"):
        with open(args.input_file_1, 'r', encoding='utf-8') as f1:
            annotated_text_1 = f1.read()
        annotated_text_1 = discover_encr(annotated_text_1, args.format_choice, 1)
        with open(args.input_file_1, 'w', encoding='utf-8') as f1:
            f1.write(annotated_text_1)
            print('discovery of encryption algorithms applied on dataset1.\n')

    if prompt_user("Would you like to apply it on Dataset 2?"):
        with open(args.input_file_2, 'r', encoding='utf-8') as f2:
            annotated_text_2 = f2.read()
        annotated_text_2 = discover_encr(annotated_text_2, args.format_choice, 2)
        with open(args.input_file_2, 'w', encoding='utf-8') as f2:
            f2.write(annotated_text_2)
            print('discovery of encryption algorithms applied on dataset2.\n')
        print('discover_encry_algorithms completed.\n')


# =================================== Discover Operating Systems=================================

def transform_OS_output(entity, tagging, label_name):
    transformed_output = []
    if tagging == 'BIOES':
        if len(entity.split()) == 1:
            entity_labels = ['S']
        if len(entity.split()) == 2:
            entity_labels = ['B', 'E']
        if len(entity.split()) == 3:
            entity_labels = ['B', 'I', 'E']
        if len(entity.split()) == 4:
            entity_labels = ['B', 'I', 'I', 'E']
        if len(entity.split()) == 5:
            entity_labels = ['B', 'I', 'I', 'I', 'E']
    if tagging == 'BIO':
        if len(entity.split()) == 1:
            entity_labels = ['B']
        if len(entity.split()) == 2:
            entity_labels = ['B', 'I']
        if len(entity.split()) == 3:
            entity_labels = ['B', 'I', 'I']
        if len(entity.split()) == 4:
            entity_labels = ['B', 'I', 'I', 'I']
        if len(entity.split()) == 5:
            entity_labels = ['B', 'I', 'I', 'I', 'I']

    for word, tag in zip(entity.split(), entity_labels):
        transformed_output.append(f"{word} {tag}-{label_name}")

    return "\n".join(transformed_output)


def get_os_by_name(name):
    name = name.lower()
    file_path = "operating_systems.csv"
    df = pd.read_csv(file_path)

    row = df[df['Operating_systems'].str.lower() == name]
    if not row.empty:
        return True
    else:
        return False


def discover_os(text, tagging, dataset_number):
    lines = text.strip().split("\n")
    updated_dataset = []
    print(f"For Dataset {dataset_number}:")
    new_label = input("Enter the label name for the operating system (eg. OS): ")
    startWith = ['windows', 'linux', 'mac', 'macos' 'Ubuntu', 'fedora', 'centos', 'RHEL', 'FreeBSD']
    startWith = [l.lower() for l in startWith]

    # new_label = 'OS'
    current_entity = ''
    if tagging == 'BIO':
        tag = 'B'
    if tagging == 'BIOES':
        tag = 'S'
    for i, line in enumerate(lines):
        # print("initial here", line)
        if line.split():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                word, label = parts
                entity = ''
                if label == 'O':
                    if word.lower() == 'android':
                        # entity += word
                        updated_dataset.append(f"{word} {tag}-{new_label}")

                    # check neiboring words
                    elif word.lower() in startWith:
                        entity += word

                        next_line = nextLine(lines, i)
                        while next_line is not None:
                            next_word, next_label = next_line.split(' ', 1)
                            if next_label[0] == 'O':
                                current_entity = entity
                                entity += ' ' + next_word

                            else:
                                entity = entity
                                break
                            # if entity.lower() in OS:
                            if get_os_by_name(entity.lower()):
                                i += 1
                                next_line = nextLine(lines, i)
                            else:
                                entity = current_entity
                                break
                        # print(entity)
                        output = transform_OS_output(entity, tagging, new_label)
                        updated_dataset.append(output)
                        # print(word,current_entity.split(' '))
                    elif word in current_entity.split(' '):
                        continue
                    else:
                        updated_dataset.append(f"{word} {label}")
                else:
                    updated_dataset.append(line)
            else:
                updated_dataset.append(line)
            current_entity = entity
    return '\n'.join(updated_dataset)


def discover_operating_systems(args):
    print("This module discovers common OS (Linux, Windows, Mac, etc ) found in CTI reports.\n")
    if prompt_user("Would you like to apply it on Dataset 1?"):
        with open(args.input_file_1, 'r', encoding='utf-8') as f1:
            annotated_text_1 = f1.read()
        annotated_text_1 = discover_os(annotated_text_1, args.format_choice, 1)
        with open(args.input_file_1, 'w', encoding='utf-8') as f1:
            f1.write(annotated_text_1)
            print('discovery OS applied on dataset1.\n')

    if prompt_user("Would you like to apply it on Dataset 2?"):
        with open(args.input_file_2, 'r', encoding='utf-8') as f2:
            annotated_text_2 = f2.read()
        annotated_text_2 = discover_os(annotated_text_2, args.format_choice, 2)
        with open(args.input_file_2, 'w', encoding='utf-8') as f2:
            f2.write(annotated_text_2)
            print('discovery OS applied on dataset2.\n')
        print('discover_operating_systems completed.\n')


# ================================ Fix mislabelling issues in the datasets for single entities =======================

def correct_mislabeling(text, dataset_number):
    print(f"Fixing mislabeling issues on dataset {dataset_number}...")
    lines = text.strip().split("\n")
    entity_labels = {}

    temp_lines = []
    for i, line in enumerate(lines):
        parts = line.split(" ", 1)
        if len(parts) == 2:
            word, label = parts
            if label.startswith('S-'):
                if word in entity_labels:
                    label = entity_labels[word]
                else:
                    entity_labels[word] = label
                temp_lines.append(f"{word} {label}")
            elif label.startswith('B-'):
                next_line = nextLine(lines, i)
                if next_line and next_line.split(' ', 1)[1].startswith('O'):
                    if word in entity_labels:
                        label = entity_labels[word]
                    else:
                        entity_labels[word] = label
                    temp_lines.append(f"{word} {label}")
                else:
                    temp_lines.append(f"{word} {label}")
            else:
                temp_lines.append(f"{word} {label}")
        else:
            temp_lines.append(line)
    # print(entity_labels)
    lines = temp_lines

    corrected_lines = []
    for line in lines:
        parts = line.split(" ", 1)
        if len(parts) == 2:
            word, label = parts
            if label == 'O' and word in entity_labels:
                corrected_lines.append(f"{word} {entity_labels[word]}")
            else:
                corrected_lines.append(line)
        else:
            corrected_lines.append(line)

    return '\n'.join(corrected_lines)


def fixingMislabeledIssue(args):
    print("This module fixes inconsistent labeling issues in the datasets.\n")
    if prompt_user("Would you like to apply it on Dataset 1?"):
        with open(args.input_file_1, 'r', encoding='utf-8') as f1:
            annotated_text_1 = f1.read()
        annotated_text_1 = correct_mislabeling(annotated_text_1, 1)
        with open(args.input_file_1, 'w', encoding='utf-8') as f1:
            f1.write(annotated_text_1)
            print("fixingMislabeledIssue applied on dataset 1.\n")

    if prompt_user("Would you like to apply it on Dataset 2?"):
        with open(args.input_file_2, 'r', encoding='utf-8') as f2:
            annotated_text_2 = f2.read()
        annotated_text_2 = correct_mislabeling(annotated_text_2, 2)
        with open(args.input_file_2, 'w', encoding='utf-8') as f2:
            f2.write(annotated_text_2)
            print("fixingMislabeledIssue aaplied on dataset 2.\n")
        print("fixingMislabeledIssue completed.\n")


def merge_datasets(dataset1_path, dataset2_path, merged_output_path):
    with open(dataset1_path, 'r', encoding='utf-8') as f1:
        dataset1_content = f1.read()

    with open(dataset2_path, 'r', encoding='utf-8') as f2:
        dataset2_content = f2.read()

    # Perform any additional processing or merging logic if needed
    merged_content = dataset1_content + '\n' + dataset2_content

    with open(merged_output_path, 'w', encoding='utf-8') as merged_file:
        merged_file.write(merged_content)


# ======================= Execution=================================
def prompt_user(message):
    while True:
        response = input(f"{message} (y/n): ").strip().lower()
        if response in ['y', 'n']:
            return response == 'y'


def main():
    parser = argparse.ArgumentParser(description='Convert BIO to BIOES format')
    parser.add_argument('format_choice', choices=['BIO', 'BIOES'], help='Output format choice')
    parser.add_argument('input_file_1', help='Path to the first input file')
    parser.add_argument('input_file_2', help='Path to the second input file')
    parser.add_argument('merged_output_file', help='Path to the merged output file')
    args = parser.parse_args()

    with open(args.input_file_1, 'r', encoding='utf-8') as f1:
        annotated_text_1 = f1.read()

    with open(args.input_file_2, 'r', encoding='utf-8') as f2:
        annotated_text_2 = f2.read()
    #
    format_1 = detect_format(annotated_text_1)
    format_2 = detect_format(annotated_text_2)
    print(format_1, format_2)

    if args.format_choice == 'BIO':
        if format_1 == 'BIOES':
            annotated_text_1 = convert_to_bio(annotated_text_1)
            print(" BIOES tagging applied on dataset 1 \n")
        if format_2 == 'BIOES':
            annotated_text_2 = convert_to_bio(annotated_text_2)
            print(" BIOES tagging applied on dataset 2 \n")

    elif args.format_choice == 'BIOES':
        if format_1 == 'BIO':
            annotated_text_1 = convert_to_bioes(annotated_text_1)
            print(" BIOES tagging applied on dataset 1 \n")
        if format_2 == 'BIO':
            annotated_text_2 = convert_to_bioes(annotated_text_2)
            print(" BIOES tagging applied on dataset 2 \n")

    else:
        raise ValueError("Invalid format choice. Use 'BIO' or 'BIOES'.")

    with open(args.input_file_1, 'w', encoding='utf-8') as f1:
        f1.write(annotated_text_1)

    with open(args.input_file_2, 'w', encoding='utf-8') as f2:
        f2.write(annotated_text_2)

    createTables()
    # ============================================================================
    print("Integration of two TI NER datasets in cyber-security")

    if prompt_user("Do you want to execute oneTo1Mappings?"):
        oneTo1Mappings(args)

    if prompt_user("Do you want to execute manyTo1Mappings?"):
        manyTo1Mappings(args)

    if prompt_user("Do you want to execute oneToManyMappings?"):
        oneToManyMappings(args)

    if prompt_user("Do you want to execute discoveryIOCs?"):
        discoveryIOCs(args)

    if prompt_user("Do you want to execute discover_encry_algorithms?"):
        discover_encry_algorithms(args)

    if prompt_user("Do you want to execute discover_operating_systems?"):
        discover_operating_systems(args)

    # if prompt_user("Do you want to execute fixingMislabeledIssue?"):
    #     fixingMislabeledIssue(args)

    # Merge datasets at the end
    if prompt_user("Do you want to execute merge_datasets?"):
        merge_datasets(args.input_file_1, args.input_file_2, args.merged_output_file)
        print("Both datasets merged successfully.")


if __name__ == '__main__':
    main()
